package storage

import (
	"time"

	"github.com/gajananan/argocd-interlace/pkg/storage/git"
	"github.com/gajananan/argocd-interlace/pkg/storage/oci"
)

type StorageBackend interface {
	StoreManifestSignature() error
	StoreManifestProvenance() error
	SetBuildFinishedOn(buildFinishedOn time.Time)
	Type() string
}

func InitializeStorageBackends(appName, appPath, appDirPath,
	appSourceRepoUrl, appSourceRevision, appSourceCommitSha, imageRef,
	manifestGitUrl, manifestGitUserId, manifestGitToken, finalManifest string,
	buildStartedOn time.Time) (map[string]StorageBackend, error) {

	//configuredStorageBackends := []string{oci.StorageBackendOCI}
	configuredStorageBackends := []string{git.StorageBackendGit}

	storageBackends := map[string]StorageBackend{}
	for _, backendType := range configuredStorageBackends {
		switch backendType {
		case oci.StorageBackendOCI:

			ociStorageBackend, err := oci.NewStorageBackend(appName, appPath, appDirPath,
				appSourceRepoUrl, appSourceRevision, appSourceCommitSha, imageRef,
				buildStartedOn)
			if err != nil {
				return nil, err
			}
			storageBackends[backendType] = ociStorageBackend

		case git.StorageBackendGit:
			gitStorageBackend, err := git.NewStorageBackend(appName, appPath, appDirPath,
				appSourceRepoUrl, appSourceRevision, appSourceCommitSha,
				manifestGitUrl, manifestGitUserId, manifestGitToken,
				buildStartedOn)
			if err != nil {
				return nil, err
			}
			storageBackends[backendType] = gitStorageBackend
		}

	}

	return storageBackends, nil

}
