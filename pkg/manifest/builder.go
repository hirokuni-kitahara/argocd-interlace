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
	"github.com/gajananan/argocd-interlace/pkg/storage"
	"github.com/gajananan/argocd-interlace/pkg/utils"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func CreateEventHandler(app *appv1.Application) {
	log.Debug("app ", app)
	appName := app.ObjectMeta.Name

	desiredManifest := retriveDesiredManifest(appName)

	items := gjson.Get(desiredManifest, "items")

	finalManifest := ""

	log.Debug("len(items.Array()) ", len(items.Array()))

	for i, item := range items.Array() {

		targetState := gjson.Get(item.String(), "targetState").String()

		finalManifest = prepareFinalManifest(targetState, finalManifest, i, len(items.Array())-1)
	}
	// if finalmanifest is empty, replace ARGOCD_TOKEN in argocd-token-secret
	if finalManifest == "" {
		log.Info("finalManifest is empty, skipping generating bundle manifest", finalManifest)
		return
	} else {

		log.Info("---------Event Received---------")
		loc, _ := time.LoadLocation("UTC")
		buildStartedOn := time.Now().In(loc)

		log.Info()
		log.Info("------------------ Source Git Repo  --------------")
		// can not use app.Status.Sync in creationEventHandler as it is nil.

		log.Info("url: ", app.Spec.Source.RepoURL)
		log.Info("path: ", app.Spec.Source.Path)
		log.Info("targetRevision: ", app.Spec.Source.TargetRevision)

		//log.Info("commit id: ", app.Status.Sync.Revision)

		// Do not use app.Status  in create event.
		appSourceRepoUrl := app.Spec.Source.RepoURL
		appSourceRevision := app.Spec.Source.TargetRevision
		//TODO: How to get revision (commitSha)
		appSourceCommitSha := app.Spec.Source.TargetRevision
		appPath := app.Spec.Source.Path

		log.Debug("app.Status ", app.Status)
		imageRef := getImageRef(appName)
		signManifestAndGenerateProvenance(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
			finalManifest, imageRef, buildStartedOn)

		log.Info("--------------------------------------------------")
		log.Info("--------- Completed Processing Event---------")
	}

}

func UpdateEventHandler(oldApp, newApp *appv1.Application) {

	generateAppDebugMsg(oldApp, newApp)

	generateManifest := false

	if oldApp.Status.Health.Status == "" &&
		oldApp.Status.OperationState != nil &&
		oldApp.Status.OperationState.Phase == "Running" &&
		oldApp.Status.Sync.Status == "" &&
		newApp.Status.Health.Status == "Missing" &&
		newApp.Status.OperationState != nil &&
		newApp.Status.OperationState.Phase == "Running" &&
		newApp.Status.Sync.Status == "OutOfSync" {
		// This branch handle the case in which app is newly created,
		// the follow updates contains the necessary information (commit hash etc.)
		generateManifest = true
	} else if oldApp.Status.OperationState != nil &&
		oldApp.Status.OperationState.Phase == "Running" &&
		oldApp.Status.Sync.Status == "Synced" &&
		newApp.Status.OperationState != nil &&
		newApp.Status.OperationState.Phase == "Running" &&
		newApp.Status.Sync.Status == "OutOfSync" {
		// This branch handle the case in which app is being updated,
		// the updates contains the necessary information (commit hash etc.)
		generateManifest = true
	}

	if generateManifest {
		loc, _ := time.LoadLocation("UTC")
		buildStartedOn := time.Now().In(loc)

		finalManifest := ""
		diffCount := 0

		appName := newApp.ObjectMeta.Name
		appPath := newApp.Status.Sync.ComparedTo.Source.Path
		appSourceRepoUrl := newApp.Status.Sync.ComparedTo.Source.RepoURL
		appSourceRevision := newApp.Status.Sync.ComparedTo.Source.TargetRevision
		appSourceCommitSha := newApp.Status.Sync.Revision

		// Retrive the bundle image name and tag based on configuration and appName
		imageRef := getImageRef(appName)

		// Check if the there is an existing bundle manifest in the storage
		bundleYAMLBytes, err := getBundleManifest(imageRef)

		// if manifest not found (== first time bundle is created for the first time),
		// create new bundle without checking if diff exist
		if err != nil {
			diffCount += 1
		}

		manifestYAMLs := k8smnfutil.SplitConcatYAMLs(bundleYAMLBytes)

		// Retrive the desired state of manifest via argocd API call
		desiredManifest := retriveDesiredManifest(appName)

		items := gjson.Get(desiredManifest, "items")

		log.Debug("len(items.Array()) ", len(items.Array()))

		// For each resource in desired manifest
		// Check if it has changed from the version that exist in the bundle manifest
		for i, item := range items.Array() {
			targetState := gjson.Get(item.String(), "targetState").String()
			if diffCount == 0 {
				diffExist := checkDiffWithBundle([]byte(targetState), manifestYAMLs)
				if diffExist {
					diffCount += 1
				}
			}
			// Add desired state of each resource to finalManifest
			finalManifest = prepareFinalManifest(targetState, finalManifest, i, len(items.Array())-1)
		}

		// if finalmanifest is empty, replace ARGOCD_TOKEN in argocd-token-secret
		if finalManifest == "" {
			log.Info("finalManifest is empty, skipping generating bundle manifest", finalManifest)
			return
		}

		log.Debug("diffCount ", diffCount)

		if finalManifest != "" && diffCount > 0 {
			log.Info("---------Event Received---------")

			log.Info()
			log.Info("------------------ Source Git Repo  --------------")
			log.Info("url: ", newApp.Status.Sync.ComparedTo.Source.RepoURL)
			log.Info("path: ", newApp.Status.Sync.ComparedTo.Source.Path)
			log.Info("targetRevision: ", newApp.Status.Sync.ComparedTo.Source.TargetRevision)
			log.Info("commit id: ", newApp.Status.Sync.Revision)

			fmt.Println()
			fmt.Println()
			fmt.Println("------------------ Desired State Manifest --------------")
			fmt.Println()
			fmt.Println(finalManifest)
			fmt.Println()

			signManifestAndGenerateProvenance(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
				finalManifest, imageRef, buildStartedOn)

			log.Info("--------------------------------------------------")
			log.Info("--------- Completed Processing Event---------")
		}

	}

}

func signManifestAndGenerateProvenance(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
	finalManifest, imageRef string, buildStartedOn time.Time) {

	appDirPath := filepath.Join(utils.TMP_DIR, appName, appPath)

	utils.WriteToFile(string(finalManifest), appDirPath, utils.MANIFEST_FILE_NAME)

	manifestGitUrl := ""

	manifestGitUrl = os.Getenv("ARGOCD_INTERLACE_MANIFEST_GITREPO_URL")

	if manifestGitUrl == "" {
		log.Info("ARGOCD_INTERLACE_MANIFEST_GITREPO_URL is empty, please specify in configuration !")
	}

	manifestGitUserId := os.Getenv("ARGOCD_INTERLACE_MANIFEST_GITREPO_USER")

	manifestGitToken := os.Getenv("ARGOCD_INTERLACE_MANIFEST_GITREPO_TOKEN")
	log.Info("calling InitializeStorageBackends")

	allStorage, err := storage.InitializeStorageBackends(appName, appPath, appDirPath,
		appSourceRepoUrl, appSourceRevision, appSourceCommitSha, imageRef,
		manifestGitUrl, manifestGitUserId, manifestGitToken, string(finalManifest),
		buildStartedOn)

	if err != nil {
		return
	}

	for _, storage := range allStorage {

		log.Info("calling StoreManifestSignature")
		storage.StoreManifestSignature()

		loc, _ := time.LoadLocation("UTC")

		buildFinishedOn := time.Now().In(loc)

		storage.SetBuildFinishedOn(buildFinishedOn)

		storage.StoreManifestProvenance()
	}

	/*err := signManifest(appDirPath, imageRef)

	if err != nil {
		log.Info("Error in signing bundle image err %s", err.Error())
		return
	}

	provenance.GenerateProvanance(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
		imageRef, buildStartedOn, buildFinishedOn)
	*/
	return
}

func getImageRef(appName string) string {

	imageRef := ""

	imageRegistry := os.Getenv("IMAGE_REGISTRY")

	if imageRegistry == "" {
		log.Info("IMAGE_REGISTRY is empty, please specify in configuration !")
		return ""
	}

	imagePrefix := os.Getenv("IMAGE_PREFIX")

	if imagePrefix == "" {
		log.Info("IMAGE_PREFIX is empty please specify in configuration!")
		return ""
	}

	imageTag := os.Getenv("IMAGE_TAG")

	if imageTag == "" {
		log.Info("IMAGE_TAG is empty please specify in configuration!")
		return ""
	}

	imageName := fmt.Sprintf("%s-%s", imagePrefix, appName)

	imageRef = fmt.Sprintf("%s/%s:%s", imageRegistry, imageName, imageTag)

	return imageRef

}

func getBundleManifest(imageRef string) ([]byte, error) {

	image, err := k8smnfutil.PullImage(imageRef)

	if err != nil {
		log.Info("Error in pulling image err %s", err.Error())
		return nil, err
	}

	concatYAMLbytes, err := k8smnfutil.GenerateConcatYAMLsFromImage(image)
	if err != nil {
		log.Info("Error in GenerateConcatYAMLsFromImage err %s", err.Error())
		return nil, err
	}
	return concatYAMLbytes, nil
}

func prepareFinalManifest(targetState, finalManifest string, counter int, numberOfitems int) string {

	var obj *unstructured.Unstructured

	err := json.Unmarshal([]byte(targetState), &obj)
	if err != nil {
		log.Info("Error in unmarshaling err %s", err.Error())
	}

	objBytes, _ := yaml.Marshal(obj)
	endLine := ""
	if !strings.HasSuffix(string(objBytes), "\n") {
		endLine = "\n"
	}

	finalManifest = fmt.Sprintf("%s%s%s", finalManifest, string(objBytes), endLine)
	finalManifest = strings.ReplaceAll(finalManifest, "object:\n", "")

	if counter < numberOfitems {
		finalManifest = fmt.Sprintf("%s---\n", finalManifest)
	}

	return finalManifest
}

func retriveDesiredManifest(appName string) string {

	baseUrl := os.Getenv("ARGOCD_API_BASE_URL")

	if baseUrl == "" {
		log.Info("ARGOCD_API_BASE_URL is empty, please specify it in configuration!")
		return ""
	}

	desiredRscUrl := fmt.Sprintf("%s/%s/managed-resources", baseUrl, appName)

	desiredManifest := utils.QueryAPI(desiredRscUrl, nil)

	return desiredManifest
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

		// when diffs == nil,  there is no difference in YAMLs being compared.
		if diffs == nil || diffs.Size() == 0 {
			found = true
			break
		}
	}
	return found

}

func signManifest(appDirPath, imageRef string) error {

	manifestFilePath := filepath.Join(appDirPath, utils.MANIFEST_FILE_NAME)
	signedManifestFilePath := filepath.Join(appDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	keyPath := utils.PRIVATE_KEY_PATH
	log.Debug("imageRef ", imageRef, " keyPath ", keyPath)

	so := &k8smanifest.SignOption{
		ImageRef:         imageRef,
		KeyPath:          keyPath,
		Output:           signedManifestFilePath,
		UpdateAnnotation: true,
		ImageAnnotations: nil,
	}

	_, err := k8smanifest.Sign(manifestFilePath, so)
	if err != nil {
		return err
	}
	return nil
}

func generateAppDebugMsg(oldApp, newApp *appv1.Application) {
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
}
