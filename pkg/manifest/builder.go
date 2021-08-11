package manifest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/IBM/integrity-enforcer/enforcer/pkg/mapnode"
	appv1 "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	"github.com/gajananan/argocd-interlace/pkg/provenance"
	"github.com/gajananan/argocd-interlace/pkg/utils"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func CreateEventHandler(app *appv1.Application, privateKeyPath, publicKeyPath string) {
	appName := app.ObjectMeta.Name

	// Do not use app.Status  in create event.
	appPath := app.Status.Sync.ComparedTo.Source.Path

	desiredManifest := retriveDesiredManifest(appName)

	items := gjson.Get(desiredManifest, "items")

	finalManifest := ""

	log.Debug("len(items.Array()) ", len(items.Array()))

	for i, item := range items.Array() {

		targetState := gjson.Get(item.String(), "targetState").String()

		finalManifest = prepareFinalManifest(targetState, finalManifest, i, len(items.Array())-1)
	}

	log.Info("---------Event Received---------")
	loc, _ := time.LoadLocation("UTC")
	buildStartedOn := time.Now().In(loc)

	log.Info()
	log.Info("------------------ Source Git Repo  --------------")

	log.Info("url: ", app.Status.Sync.ComparedTo.Source.RepoURL)
	log.Info("path: ", app.Status.Sync.ComparedTo.Source.Path)
	log.Info("targetRevision: ", app.Status.Sync.ComparedTo.Source.TargetRevision)
	log.Info("commit id: ", app.Status.Sync.Revision)

	appSourceRepoUrl := app.Status.Sync.ComparedTo.Source.RepoURL
	appSourceRevision := app.Status.Sync.ComparedTo.Source.TargetRevision
	appSourceCommitSha := app.Status.Sync.Revision
	log.Info("app.Status ", app.Status)
	imageRef := getImageRef(appName, appPath, appSourceRepoUrl)

	signAndGenerateProvenance(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
		finalManifest, imageRef, privateKeyPath, publicKeyPath, buildStartedOn)

	log.Info("--------------------------------------------------")
	log.Info("--------- Completed Processing Event---------")

}

func UpdateEventHandler(oldApp, newApp *appv1.Application, privateKeyPath, publicKeyPath string) {
	appName := newApp.ObjectMeta.Name
	appPath := newApp.Status.Sync.ComparedTo.Source.Path

	log.Debug(fmt.Sprintf("oldApp.Status.Health.Status %s ", oldApp.Status.Health.Status))

	if oldApp.Status.OperationState != nil {
		log.Debug(fmt.Sprintf("oldApp.Status.OperationState.Phase %s ", oldApp.Status.OperationState.Phase))

	} else {
		log.Debug(fmt.Sprintf("oldApp.Status.OperationState %s ", oldApp.Status.OperationState))
	}

	log.Debug(fmt.Sprintf("oldApp.Status.Sync.Status %s ", oldApp.Status.Sync.Status))

	log.Debug(fmt.Sprintf("newApp.Status.Health.Status %s ", newApp.Status.Health.Status))

	if newApp.Status.OperationState != nil {
		log.Debug(fmt.Sprintf("newApp.Status.OperationState.Phase %s ", newApp.Status.OperationState.Phase))
	} else {
		log.Debug(fmt.Sprintf("newApp.Status.OperationState %s ", newApp.Status.OperationState))
	}

	log.Debug(fmt.Sprintf("newApp.Status.Sync.Status %s ", newApp.Status.Sync.Status))

	if oldApp.Status.OperationState != nil &&
		oldApp.Status.OperationState.Phase == "Running" &&
		oldApp.Status.Sync.Status == "Synced" &&
		newApp.Status.OperationState != nil &&
		newApp.Status.OperationState.Phase == "Running" &&
		newApp.Status.Sync.Status == "OutOfSync" {

		finalManifest := ""

		diffCount := 0

		appSourceRepoUrl := newApp.Status.Sync.ComparedTo.Source.RepoURL
		appSourceRevision := newApp.Status.Sync.ComparedTo.Source.TargetRevision
		appSourceCommitSha := newApp.Status.Sync.Revision
		imageRef := getImageRef(appName, appPath, appSourceRepoUrl)

		bundleYAMLBytes, err := getBundleManifest(imageRef)
		// if manifest not found, create new bundle without checking if diff exist
		if err != nil {
			diffCount += 1
		}

		manifestYAMLs := k8smnfutil.SplitConcatYAMLs(bundleYAMLBytes)

		desiredManifest := retriveDesiredManifest(appName)
		items := gjson.Get(desiredManifest, "items")
		log.Debug("len(items.Array()) ", len(items.Array()))

		for i, item := range items.Array() {

			targetState := gjson.Get(item.String(), "targetState").String()

			if diffCount == 0 {
				diffExist := checkDiffWithBundle([]byte(targetState), manifestYAMLs)
				if diffExist {
					diffCount += 1
				}
			}

			finalManifest = prepareFinalManifest(targetState, finalManifest, i, len(items.Array())-1)
		}

		log.Info("diffCount ", diffCount)
		if diffCount > 0 {
			log.Info("---------Event Received---------")
			loc, _ := time.LoadLocation("UTC")
			buildStartedOn := time.Now().In(loc)

			log.Info()
			log.Info("------------------ Source Git Repo  --------------")
			/*
				log.Info("url: ", oldApp.Status.Sync.ComparedTo.Source.RepoURL)
				log.Info("path: ", oldApp.Status.Sync.ComparedTo.Source.Path)
				log.Info("targetRevision: ", oldApp.Status.Sync.ComparedTo.Source.TargetRevision)
				log.Info("commit id: ", oldApp.Status.Sync.Revision)
				log.Info(oldApp.Status.History)
				log.Info("----------")
			*/

			log.Info("url: ", newApp.Status.Sync.ComparedTo.Source.RepoURL)
			log.Info("path: ", newApp.Status.Sync.ComparedTo.Source.Path)
			log.Info("targetRevision: ", newApp.Status.Sync.ComparedTo.Source.TargetRevision)
			log.Info("commit id: ", newApp.Status.Sync.Revision)

			// if finalmanifest is empty, replace ARGOCD_TOKEN in argocd-token-secret
			if finalManifest == "" {
				log.Info("finalManifest is empty", finalManifest)
			}
			signAndGenerateProvenance(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
				finalManifest, imageRef, privateKeyPath, publicKeyPath, buildStartedOn)

			log.Info("--------------------------------------------------")
			log.Info("--------- Completed Processing Event---------")
		}

	}

}

func getImageRef(appName, appPath, appSourceRepoUrl string) string {
	imageRef := ""
	tokens := strings.Split(appSourceRepoUrl, "/")
	if len(tokens) > 2 {
		repoName := tokens[3]
		imageRegistry := os.Getenv("IMAGE_REGISTRY")
		imageName := fmt.Sprintf("%s-%s", repoName, appName)
		tag := strings.ReplaceAll(appPath, "/", "-")
		imageRef = fmt.Sprintf("%s/%s:%s", imageRegistry, imageName, tag)
	}
	return imageRef
}

func getBundleManifest(imageRef string) ([]byte, error) {

	image, err := k8smnfutil.PullImage(imageRef)

	if err != nil {
		log.Info("Error in pulling image err %s", err.Error())
		return nil, err
	}

	imageManifest, _ := image.RawManifest()
	log.Debug("imageManifest ", string(imageManifest))

	concatYAMLbytes, err := k8smnfutil.GenerateConcatYAMLsFromImage(image)
	if err != nil {
		log.Info("Error in GenerateConcatYAMLsFromImage err %s", err.Error())
		return nil, err
	}
	return concatYAMLbytes, nil
}

func prepareFinalManifest(targetState, finalManifest string, counter int, numberOfitem int) string {
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
	if counter < numberOfitem {
		finalManifest = fmt.Sprintf("%s---\n", finalManifest)
	}
	return finalManifest
}

func retriveDesiredManifest(appName string) string {

	baseUrl := os.Getenv("ARGOCD_API_BASE_URL")

	desiredRscUrl := fmt.Sprintf("%s/%s/managed-resources", baseUrl, appName)

	desiredManifest := utils.QueryAPI(desiredRscUrl, nil)

	return desiredManifest
}

func signAndGenerateProvenance(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
	finalManifest, imageRef, privateKeyPath, publicKeyPath string, buildStartedOn time.Time) {

	fmt.Println()
	fmt.Println()
	fmt.Println("------------------ Desired State Manifest --------------")
	fmt.Println()

	dirPath := filepath.Join("/tmp/output", appName, appPath)
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		os.MkdirAll(dirPath, os.ModePerm)
	}
	fmt.Println(finalManifest)
	outfilepath := filepath.Join(dirPath, "manifest.yaml")

	utils.WriteToFile(string(finalManifest), outfilepath)

	signManifest(outfilepath, imageRef, privateKeyPath)

	loc, _ := time.LoadLocation("UTC")
	buildFinishedOn := time.Now().In(loc)

	provenance.GenerateProvanance(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha, privateKeyPath, publicKeyPath, imageRef, buildStartedOn, buildFinishedOn)

}

func checkDiffWithBundle(targetObjYAMLBytes []byte, manifestYAMLs [][]byte) bool {

	objNode, err := mapnode.NewFromBytes(targetObjYAMLBytes) // json
	log.Debug("targetObjYAMLBytes ", string(targetObjYAMLBytes))
	if err != nil {
		log.Fatalf("objNode error from NewFromYamlBytes %s", err.Error())
		// do somthing
	}
	found := false
	for _, manifest := range manifestYAMLs {

		mnfNode, err := mapnode.NewFromYamlBytes(manifest)
		if err != nil {
			log.Fatalf("mnfNode error from NewFromYamlBytes %s", err.Error())
			// do somthing
		}
		diffs := objNode.Diff(mnfNode)

		if diffs == nil || diffs.Size() == 0 {
			found = true
			break
		}
	}
	return found

}

func signManifest(inputDir, imageRef, keyPath string) error {
	log.Info("imageRef ", imageRef, " keyPath ", keyPath)
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
