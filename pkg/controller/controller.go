package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	appClientset "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned"
	"github.com/gajananan/argocd-interlace/pkg/utils"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	mapnode "github.com/sigstore/k8s-manifest-sigstore/pkg/util/mapnode"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	apiruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type controller struct {
	applicationClientset appClientset.Interface
	informer             cache.SharedIndexInformer
	appRefreshQueue      workqueue.RateLimitingInterface
	namespace            string
	debug                bool
}

const (
	ARGOCD_API_BASE_URL = "https://argo-route-argocd.apps.ma4kmc2.openshiftv4test.com/api/v1/applications/"
	KEY_PATH            = "/etc/signing-secrets/cosign.key"
)

func Start(ctx context.Context, config string, namespace string, debug bool) {
	_, cfg, err := utils.GetClient(config, debug)
	appClientset := appClientset.NewForConfigOrDie(cfg)
	if err != nil {
		logrus.Fatal(err)
	}

	c := newController(appClientset, namespace, debug)
	c.Run(ctx)
}

func (ctrl *controller) newApplicationInformer(applicationClientset appClientset.Interface) cache.SharedIndexInformer {

	informer := cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (apiruntime.Object, error) {
				return applicationClientset.ArgoprojV1alpha1().Applications(ctrl.namespace).List(context.TODO(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return applicationClientset.ArgoprojV1alpha1().Applications(ctrl.namespace).Watch(context.TODO(), options)
			},
		},
		&appv1.Application{},
		0,
		cache.Indexers{},
	)
	return informer
}

func newController(applicationClientset appClientset.Interface, namespace string, debug bool /*, clientOpts *argocdclient.ClientOptions*/) *controller {
	q := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	ctrl := &controller{
		applicationClientset: applicationClientset,
		appRefreshQueue:      q,
		namespace:            namespace,
		debug:                debug,
	}

	appInformer := ctrl.newApplicationInformer(applicationClientset)
	appInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if !ctrl.canProcessApp(obj) {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				if ctrl.debug {
					logrus.Infof("Event received of type create for key [%s] ", key)
				}
				ctrl.appRefreshQueue.Add(key)
				if ctrl.debug {
					logrus.Infof("Event queue size: %v", ctrl.appRefreshQueue.Len())
				}
			}

		},
		UpdateFunc: func(old, new interface{}) {
			if !ctrl.canProcessApp(old) {
				return
			}
			key, err := cache.MetaNamespaceKeyFunc(old)

			oldApp, oldOK := old.(*appv1.Application)
			newApp, newOK := new.(*appv1.Application)
			if oldOK && newOK {
				appName := newApp.ObjectMeta.Name
				rolePath := newApp.Status.Sync.ComparedTo.Source.Path
				//logrus.Infof("oldApp.Status.OperationState.Phase ", oldApp.Status.OperationState)
				//logrus.Infof("newApp %s ", newApp)

				//logrus.Infof("newApp.Status %s ", newApp.Status)

				//logrus.Infof("newApp.Status.OperationState %s ", newApp.Status.OperationState)

				if ctrl.debug {

					logrus.Infof("oldApp.Status ", oldApp.Status)
					logrus.Infof("-------------------------")
					logrus.Infof("newApp.Status ", newApp.Status)
				}

				if ctrl.debug {
					fmt.Println(fmt.Sprintf("oldApp.Status.Health.Status %s ", oldApp.Status.Health.Status))
					if oldApp.Status.OperationState != nil {
						fmt.Println(fmt.Sprintf("oldApp.Status.OperationState.Phase %s ", oldApp.Status.OperationState.Phase))
					} else {
						fmt.Println(fmt.Sprintf("oldApp.Status.OperationState %s ", oldApp.Status.OperationState))
					}

					fmt.Println(fmt.Sprintf("oldApp.Status.Sync.Status %s ", oldApp.Status.Sync.Status))

					fmt.Println(fmt.Sprintf("newApp.Status.Health.Status %s ", newApp.Status.Health.Status))

					if newApp.Status.OperationState != nil {
						fmt.Println(fmt.Sprintf("newApp.Status.OperationState.Phase %s ", newApp.Status.OperationState.Phase))
					} else {
						fmt.Println(fmt.Sprintf("newApp.Status.OperationState %s ", newApp.Status.OperationState))
					}

					fmt.Println(fmt.Sprintf("newApp.Status.Sync.Status %s ", newApp.Status.Sync.Status))
				}

				if oldApp.Status.OperationState != nil &&
					oldApp.Status.OperationState.Phase == "Running" &&
					oldApp.Status.Sync.Status == "Synced" && //"OutOfSync" && //"Synced" &&
					newApp.Status.OperationState != nil &&
					newApp.Status.OperationState.Phase == "Running" &&
					newApp.Status.Sync.Status == "OutOfSync" {

					desiredRscUrl := fmt.Sprintf("%s/%s/managed-resources", ARGOCD_API_BASE_URL, appName)

					desiredManifest := queryAPI(desiredRscUrl, nil)

					items := gjson.Get(desiredManifest, "items")
					finalManifest := ""
					//fmt.Println("len(items.Array()) ", len(items.Array()))
					diffCount := 0
					for i, item := range items.Array() {

						targetState := gjson.Get(item.String(), "targetState").String()
						liveState := gjson.Get(item.String(), "liveState").String()

						kind := gjson.Get(targetState, "kind").String()
						name := gjson.Get(targetState, "metadata.name").String()
						if ctrl.debug {
							if kind == "Deployment" && name == "akme-account-command" {
								targetImage := gjson.Get(targetState, "spec.template.spec.containers.0.image").String()
								liveImage := gjson.Get(liveState, "spec.template.spec.containers.0.image").String()
								fmt.Println(fmt.Sprintf("targetState image %s", targetImage))
								fmt.Println(fmt.Sprintf("liveState image: %s", liveImage))

								targetManifestNode, err := mapnode.NewFromYamlBytes([]byte(targetState))
								liveManifestNode, err := mapnode.NewFromYamlBytes([]byte(liveState))
								liveManifestNodeMaked := liveManifestNode.Mask(maskKeys)

								if err != nil {
									fmt.Println("Compare error")
								}
								diff := targetManifestNode.Diff(liveManifestNodeMaked)
								fmt.Println("diff:", diff)

							}
						}
						diffExist := checkDiff(targetState, liveState)
						if diffExist {
							diffCount += 1
						}
						var obj *unstructured.Unstructured
						err := json.Unmarshal([]byte(targetState), &obj)
						if err != nil {
						}
						objBytes, _ := yaml.Marshal(obj)
						endLine := ""
						if !strings.HasSuffix(string(objBytes), "\n") {
							endLine = "\n"
						}
						finalManifest = fmt.Sprintf("%s%s%s", finalManifest, string(objBytes), endLine)
						finalManifest = strings.ReplaceAll(finalManifest, "object:\n", "")
						if i < len(items.Array())-1 {
							finalManifest = fmt.Sprintf("%s---\n", finalManifest)
						}

					}

					if diffCount > 0 {
						fmt.Println("---------Event Recieved---------")
						fmt.Println()
						fmt.Println("------------------ Source Git Repo  --------------")
						/*
							fmt.Println("url: ", oldApp.Status.Sync.ComparedTo.Source.RepoURL)
							fmt.Println("path: ", oldApp.Status.Sync.ComparedTo.Source.Path)
							fmt.Println("targetRevision: ", oldApp.Status.Sync.ComparedTo.Source.TargetRevision)
							fmt.Println("commit id: ", oldApp.Status.Sync.Revision)
							fmt.Println(oldApp.Status.History)
							fmt.Println("----------")
						*/

						fmt.Println("url: ", newApp.Status.Sync.ComparedTo.Source.RepoURL)
						fmt.Println("path: ", newApp.Status.Sync.ComparedTo.Source.Path)
						fmt.Println("targetRevision: ", newApp.Status.Sync.ComparedTo.Source.TargetRevision)
						fmt.Println("commit id: ", newApp.Status.Sync.Revision)

						fmt.Println()
						fmt.Println()
						fmt.Println("------------------ Desired State Manifest --------------")
						fmt.Println()
						//fmt.Println(finalManifest)
						dirPath := filepath.Join("/tmp/output", appName, rolePath)
						if _, err := os.Stat(dirPath); os.IsNotExist(err) {
							os.MkdirAll(dirPath, os.ModePerm)
						}
						fmt.Println(finalManifest)
						outfilepath := filepath.Join(dirPath, "manifest.yaml")
						writeToFile(string(finalManifest), outfilepath)

						imageRef := "gcr.io/kg-image-registry/akeme-signed-dev:1.0.0"

						//imageRef := "gcr.io/hk-image-registry/akeme-signed-dev:1.0.0"

						signManifest(outfilepath, imageRef, KEY_PATH)
						//fmt.Println("Error ", err)
						fmt.Println("--------------------------------------------------")
						fmt.Println("--------- Completed Processing Event---------")
					}

				}

			}
			if err == nil {
				if ctrl.debug {
					logrus.Infof("Event received of type update for  [%s] ", key)
				}
				ctrl.appRefreshQueue.Add(key)
				if ctrl.debug {
					logrus.Infof("Event queue size: %v ", ctrl.appRefreshQueue.Len())
				}
			}

		},
		DeleteFunc: func(obj interface{}) {
			if !ctrl.canProcessApp(obj) {
				return
			}
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)

			if err == nil {
				if ctrl.debug {
					logrus.Infof("Event received of type delete for key [%s] ", key)
				}
				//ctrl.appRefreshQueue.Add(key)
				if ctrl.debug {
					logrus.Infof("Event queue size %v", ctrl.appRefreshQueue.Len())
				}
			}

		},
	})

	ctrl.informer = appInformer
	return ctrl
}

func writeToFile(str string, filename string) {

	f, err := os.Create(filename)
	if err != nil {

		fmt.Println("Error opening ", filename)
	}

	defer f.Close()
	_, err = f.WriteString(str)
	if err != nil {
		fmt.Println("Error writing ", filename)
	}

}

var maskKeys = []string{
	"metadata.annotations.\"deployment.kubernetes.io/revision\"",
	"metadata.annotations.\"kubectl.kubernetes.io/last-applied-configuration\"",
	"metadata.managedFields",
	"metadata.generation",
	"metadata.creationTimestamp",
	"metadata.resourceVersion",
	"metadata.selfLink",
	"metadata.uid",
	"spec.progressDeadlineSeconds",
	"spec.strategy.rollingUpdate.maxSurge",
	"spec.strategy.rollingUpdate.maxUnavailable",
	"spec.strategy.type",
	"spec.template.spec.schedulerName",
	"spec.template.spec.containers.0.terminationMessagePath",
	"spec.template.spec.containers.0.terminationMessagePolicy",
	"spec.template.spec.dnsPolicy",
	"spec.template.spec.restartPolicy",
	"spec.template.spec.terminationGracePeriodSeconds",
	"spec.template.spec.volumes.0.secret.defaultMode",
	"status",
	"spec.clusterIP",
	"spec.clusterIPs",
	"spec.sessionAffinity",
	"spec.host",
	"spec.type",
}

func checkDiff(targetState, liveState string) bool {

	targetManifestNode, err := mapnode.NewFromYamlBytes([]byte(targetState))
	liveManifestNode, err := mapnode.NewFromYamlBytes([]byte(liveState))
	liveManifestNodeMaked := liveManifestNode.Mask(maskKeys)

	if err != nil {
		fmt.Println("Compare error")
	}

	diff := targetManifestNode.Diff(liveManifestNodeMaked)
	//fmt.Println("diff:", diff)

	if diff != nil {
		return true
	}
	return false
}
func signManifest(inputDir, imageRef, keyPath string) error {
	so := &k8smanifest.SignOption{
		ImageRef:         imageRef,
		KeyPath:          keyPath,
		Output:           "/tmp/output/manifest.signed",
		UpdateAnnotation: true,
		ImageAnnotations: nil,
	}

	_, err := k8smanifest.Sign(inputDir, so)
	if err != nil {
		return err
	}
	return nil
}

func queryAPI(url string, data map[string]string) string {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	token := os.Getenv("ARGOCD_TOKEN")
	var bearer = fmt.Sprintf("Bearer %s", token)
	var dataJson []byte
	if data != nil {
		dataJson, _ = json.Marshal(data)
	} else {
		dataJson = nil
	}
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(dataJson))
	if err != nil {
		logrus.Infof("Error %s ", err)
	}

	req.Header.Add("Authorization", bearer)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logrus.Infof("Error %s ", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Infof("Error %s ", err)
	}

	return string([]byte(body))
}

func (c *controller) canProcessApp(obj interface{}) bool {
	_, ok := obj.(*appv1.Application)
	if !ok {
		return false
	}
	return true
}

func (c *controller) Run(ctx context.Context) {

	defer utilruntime.HandleCrash()    //this will handle panic and won't crash the process
	defer c.appRefreshQueue.ShutDown() //shutdown all workqueue and terminate all workers

	logrus.Info("Starting argocd-interlace...")

	go c.informer.Run(ctx.Done())

	logrus.Info("Synchronizing events...")

	//synchronize the cache before starting to process events
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		logrus.Info("synchronization failed...")
		return
	}

	logrus.Info("Synchronization complete!")
	logrus.Info("Ready to process events")

	go wait.Until(func() {
		for c.processNextItem() {
			// continue looping
		}
	}, time.Second, ctx.Done())
	<-ctx.Done()
}

func (c *controller) processNextItem() (processNext bool) {
	if c.debug {
		logrus.Info("Check if new events in queue ", c.appRefreshQueue.Len())
	}
	appKey, shutdown := c.appRefreshQueue.Get()

	if shutdown {
		processNext = false
		return
	}

	processNext = true
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorf("Recovered from panic: %+v\n%s", r, debug.Stack())
		}
		c.appRefreshQueue.Done(appKey)
	}()

	err := c.processItem(appKey.(string))
	if err == nil {
		c.appRefreshQueue.Forget(appKey)
		return true
	}
	return true
}

func (c *controller) processItem(key string) error {
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("Error fetching object with key %s from store: %v", key, err)
	}

	if !exists {
		// This happens after app was deleted, but the work queue still had an entry for it.
		return nil
	}
	_, ok := obj.(*appv1.Application)
	if !ok {
		logrus.Warnf("Key '%s' in index is not an application", key)
		return nil
	}
	//Use a switch clause instead and process the events based on the type
	if c.debug {
		logrus.Infof("argocd- has processed 1 event for object [%s]", obj)
	}
	return nil
}
