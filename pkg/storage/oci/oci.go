package oci

import (
	"path/filepath"
	"time"

	"github.com/gajananan/argocd-interlace/pkg/provenance"
	"github.com/gajananan/argocd-interlace/pkg/utils"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/k8smanifest"
	log "github.com/sirupsen/logrus"
)

type StorageBackend struct {
	appName            string
	appPath            string
	appDirPath         string
	appSourceRepoUrl   string
	appSourceRevision  string
	appSourceCommitSha string
	imageRef           string
	buildStartedOn     time.Time
	buildFinishedOn    time.Time
}

const (
	StorageBackendOCI = "oci"
)

func NewStorageBackend(appName, appPath, appDirPath,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha, imageRef string,
	buildStartedOn time.Time) (*StorageBackend, error) {
	return &StorageBackend{
		appName:            appName,
		appPath:            appPath,
		appDirPath:         appDirPath,
		appSourceRepoUrl:   appSourceRepoUrl,
		appSourceRevision:  appSourceRevision,
		appSourceCommitSha: appSourceCommitSha,
		imageRef:           imageRef,
		buildStartedOn:     buildStartedOn,
	}, nil
}

func (s StorageBackend) StoreManifestSignature() error {

	err := signManifest(s.appDirPath, s.imageRef)

	if err != nil {
		log.Info("Error in signing bundle image err %s", err.Error())
		return err
	}
	return nil
}

func (s StorageBackend) StoreManifestProvenance() error {
	provenance.GenerateProvanance(s.appName, s.appPath, s.appSourceRepoUrl, s.appSourceRevision, s.appSourceCommitSha,
		s.imageRef, s.buildStartedOn, s.buildFinishedOn)
	return nil
}

func (s StorageBackend) SetBuildFinishedOn(buildFinishedOn time.Time) {
	s.buildFinishedOn = buildFinishedOn
}

func (b *StorageBackend) Type() string {
	return StorageBackendOCI
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
