package git

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/gajananan/argocd-interlace/pkg/utils"
	billy "github.com/go-git/go-billy/v5"
	memfs "github.com/go-git/go-billy/v5/memfs"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	"github.com/tidwall/gjson"

	"github.com/go-git/go-git/v5/plumbing/object"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	memory "github.com/go-git/go-git/v5/storage/memory"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	log "github.com/sirupsen/logrus"
)

type StorageBackend struct {
	appName            string
	appPath            string
	appDirPath         string
	appSourceRepoUrl   string
	appSourceRevision  string
	appSourceCommitSha string
	manifestGitUrl     string
	manifestGitUserId  string
	manifestGitToken   string
	buildStartedOn     time.Time
	buildFinishedOn    time.Time
	manifest           []byte
}

const (
	StorageBackendGit = "git"
)

func NewStorageBackend(appName, appPath, appDirPath,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha, manifestGitUrl, manifestGitUserId, manifestGitToken string,
	buildStartedOn time.Time) (*StorageBackend, error) {
	return &StorageBackend{
		appName:            appName,
		appPath:            appPath,
		appDirPath:         appDirPath,
		appSourceRepoUrl:   appSourceRepoUrl,
		appSourceRevision:  appSourceRevision,
		appSourceCommitSha: appSourceCommitSha,
		manifestGitUrl:     manifestGitUrl,
		manifestGitUserId:  manifestGitUserId,
		manifestGitToken:   manifestGitToken,
		buildStartedOn:     buildStartedOn,
	}, nil
}

func (s StorageBackend) StoreManifestSignature() error {

	signManifest(s.appDirPath)

	configFilePath := filepath.Join(s.appDirPath, utils.CONFIG_FILE_NAME)

	signedManifestFilePath := filepath.Join(s.appDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	name := s.appName + "-cosign-keyed-sig"
	out, err := k8smnfutil.CmdExec("/ishield-app/generate_signedcm.sh", signedManifestFilePath, name, configFilePath)

	if err != nil {
		log.Info("error is generating signed configmap ", err.Error())
	}
	log.Info(out)
	s.gitCloneAndUpdate()

	return nil
}

func (s StorageBackend) StoreManifestProvenance() error {
	return nil
}
func (s StorageBackend) SetBuildFinishedOn(buildFinishedOn time.Time) {
	s.buildFinishedOn = buildFinishedOn
}
func (b *StorageBackend) Type() string {
	return StorageBackendGit
}

var storer *memory.Storage
var fs billy.Filesystem

func (s StorageBackend) gitCloneAndUpdate() {
	log.Info("Cloning repo ", s.manifestGitUrl)
	f := memfs.New()

	repo, err := git.Clone(memory.NewStorage(), f, &git.CloneOptions{
		URL: s.manifestGitUrl,
		Auth: &http.BasicAuth{
			Username: s.manifestGitUserId,
			Password: s.manifestGitToken,
		},
	})

	if err != nil {
		log.Info("Error in clone repo %s", err.Error())
	}
	w, err := repo.Worktree()

	//fileDirPath := filepath.Join(".", s.appPath)

	absFilePath := filepath.Join(s.appName, s.appPath, utils.CONFIG_FILE_NAME)

	log.Info("absFilePath ", absFilePath)

	f.Remove(absFilePath)

	//file, err := fs.OpenFile(absFilePath, os.O_RDWR|os.O_CREATE, 0666)

	file, err := f.Create(absFilePath)

	if err != nil {
		log.Fatalf("Error occured while opening file %s :%v", absFilePath, err)
	}

	configFilePath := filepath.Join(s.appDirPath, utils.CONFIG_FILE_NAME)
	configFileBytes, _ := ioutil.ReadFile(filepath.Clean(configFilePath))

	log.Info("configFileBytes ", string(configFileBytes))
	_, err = file.Write(configFileBytes)
	file.Close()

	if err != nil {
		log.Fatalf("Error occured while writing to file %s :%v", absFilePath, err)
	}

	status, _ := w.Status()
	log.Info("Git status before adding new file", status)

	// git add absFilePath
	w.Add(absFilePath)

	// Run git status after the file has been added adding to the worktree
	status, _ = w.Status()
	log.Info("Git status after adding new file ", status)

	// git commit -m $message
	_, err = w.Commit("Added my new file", getCommitOptions())
	if err != nil {
		log.Fatalf("Error occured while committing file %s :%v", absFilePath, err)
	}

	iter, _ := repo.CommitObjects()

	for {
		item, err := iter.Next()
		fmt.Println("------------")
		fmt.Println(item, err)
		fmt.Println("------------")
		if err != nil {
			break
		}

	}

	status, _ = w.Status()
	log.Info("Git status after commiting new file ", status)

	if status.IsClean() {
		log.Info("Git status after commiting new file ", status.IsClean())
	}

	dir := filepath.Join(s.appName, s.appPath)

	fileInfo, _ := w.Filesystem.ReadDir(dir)

	for _, v := range fileInfo {
		fmt.Println("fileName ", v.Name(), v.IsDir())

	}

	log.Info("Pushing changes to manifest file ")
	//Push the code to the remote
	err = repo.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth: &http.BasicAuth{
			Username: s.manifestGitUserId,
			Password: s.manifestGitToken,
		},
	})
	if err != nil {
		log.Info("Error in pushing to repo %s", err.Error())
	}
}

func getCommitOptions() *git.CommitOptions {
	return &git.CommitOptions{
		Author: &object.Signature{
			Name:  "gajananan",
			Email: "gajan@jp.ibm.com",
			When:  time.Now(),
		},
	}
}

func signManifest(appDirPath string) error {

	manifestFilePath := filepath.Join(appDirPath, utils.MANIFEST_FILE_NAME)
	signedManifestFilePath := filepath.Join(appDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	keyPath := utils.PRIVATE_KEY_PATH

	so := &k8smanifest.SignOption{
		ImageRef:         "",
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

func getSignatureMessage(appDirPath string) (string, string) {
	signedManifestFilePath := filepath.Join(appDirPath, utils.SIGNED_MANIFEST_FILE_NAME)

	signedManifestYamlBytes, _ := ioutil.ReadFile(filepath.Clean(signedManifestFilePath))

	signedManifestYAMLs := k8smnfutil.SplitConcatYAMLs(signedManifestYamlBytes)

	signature := ""
	message := ""
	for _, item := range signedManifestYAMLs {
		log.Info("signedYaml ", string(item))

		sig := gjson.Get(string(item), "metadata.annotations.\"cosign.sigstore.dev/signature\"")

		signature = sig.String()
		msg := gjson.Get(string(item), "metadata.annotations.\"cosign.sigstore.dev/message\"")
		message = msg.String()

		if signature != "" && message != "" {
			break
		}
	}

	return signature, message
}
