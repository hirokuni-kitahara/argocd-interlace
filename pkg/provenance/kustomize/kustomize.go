//
// Copyright 2021 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package kustomize

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/argoproj-labs/argocd-interlace/pkg/application"
	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance"
	"github.com/argoproj-labs/argocd-interlace/pkg/provenance/attestation"
	"github.com/argoproj-labs/argocd-interlace/pkg/utils"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
	kustbuildutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/manifestbuild/kustomize"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

type Provenance struct {
	appData application.ApplicationData
	ref     *provenance.ProvenanceRef
}

const (
	ProvenanceAnnotation = "kustomize"
)

func NewProvenance(appData application.ApplicationData) (*Provenance, error) {
	return &Provenance{
		appData: appData,
	}, nil
}

func (p *Provenance) GenerateProvanance(target, targetDigest string, uploadTLog bool, buildStartedOn time.Time, buildFinishedOn time.Time) error {
	appName := p.appData.AppName
	appPath := p.appData.AppPath
	appSourceRepoUrl := p.appData.AppSourceRepoUrl
	appSourceRevision := p.appData.AppSourceRevision
	appSourceCommitSha := p.appData.AppSourceCommitSha

	appDirPath := filepath.Join(utils.TMP_DIR, appName, appPath)

	manifestFile := filepath.Join(appDirPath, utils.MANIFEST_FILE_NAME)
	recipeCmds := []string{"", ""}

	host, orgRepo, path, gitRef, gitSuff := ParseGitUrl(appSourceRepoUrl)
	log.Info("host:", host, " orgRepo:", orgRepo, " path:", path, " gitRef:", gitRef, " gitSuff:", gitSuff)

	url := host + orgRepo + gitSuff
	log.Info("url:", url)

	r, err := GetTopGitRepo(url, appSourceRevision)

	if err != nil {
		log.Errorf("Error git clone:  %s", err.Error())
		return err
	}

	log.Info("r.RootDir ", r.RootDir, "appPath ", appPath)

	baseDir := filepath.Join(r.RootDir, appPath)

	prov, err := kustbuildutil.GenerateProvenance(manifestFile, "", baseDir, buildStartedOn, buildFinishedOn, recipeCmds)

	if err != nil {
		log.Infof("err in prov: %s ", err.Error())
	}

	provBytes, err := json.Marshal(prov)

	subjects := []in_toto.Subject{}

	targetDigest = strings.ReplaceAll(targetDigest, "sha256:", "")
	subjects = append(subjects, in_toto.Subject{Name: target,
		Digest: in_toto.DigestSet{
			"sha256": targetDigest,
		},
	})

	materials := generateMaterial(appName, appPath, appSourceRepoUrl, appSourceRevision,
		appSourceCommitSha, string(provBytes))

	entryPoint := "kustomize build"
	recipe := in_toto.ProvenanceRecipe{
		EntryPoint: entryPoint,
		Arguments:  []string{appPath},
	}

	it := in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type:          in_toto.StatementInTotoV01,
			PredicateType: in_toto.PredicateSLSAProvenanceV01,
			Subject:       subjects,
		},
		Predicate: in_toto.ProvenancePredicate{
			Metadata: &in_toto.ProvenanceMetadata{
				Reproducible:    true,
				BuildStartedOn:  &buildStartedOn,
				BuildFinishedOn: &buildFinishedOn,
			},

			Materials: materials,
			Recipe:    recipe,
		},
	}
	b, err := json.Marshal(it)
	if err != nil {
		log.Errorf("Error in marshaling attestation:  %s", err.Error())
		return err
	}

	err = utils.WriteToFile(string(b), appDirPath, utils.PROVENANCE_FILE_NAME)
	if err != nil {
		log.Errorf("Error in writing provenance to a file:  %s", err.Error())
		return err
	}

	provRef, err := attestation.GenerateSignedAttestation(it, appName, appDirPath, uploadTLog)
	if err != nil {
		log.Errorf("Error in generating signed attestation:  %s", err.Error())
		return err
	}
	if provRef != nil {
		p.ref = provRef
	}

	return nil
}

func (p *Provenance) VerifySourceMaterial() (VerifyResult, error) {
	appPath := p.appData.AppPath
	appSourceRepoUrl := p.appData.AppSourceRepoUrl
	appSourceRevision := p.appData.AppSourceRevision

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in getting interlace config:  %s", err.Error())
		return VerifyResult{}, err
	}

	if appPath == "" {
		host, orgRepo, path, gitRef, gitSuff := ParseGitUrl(appSourceRepoUrl)

		log.Info("appSourceRepoUrl ", appSourceRepoUrl)

		log.Info("host:", host, " orgRepo:", orgRepo, " path:", path, " gitRef:", gitRef, " gitSuff:", gitSuff)

		url := host + orgRepo + gitSuff

		log.Info("url:", url)

		r, err := GetTopGitRepo(url, appSourceRevision)
		if err != nil {
			log.Errorf("Error git clone:  %s", err.Error())
			return VerifyResult{}, err
		}
		appPath = r.RootDir
	}

	baseDir := appPath

	keyPath := utils.GetPubkeyPath()

	srcMatPath := filepath.Join(baseDir, interlaceConfig.SourceMaterialHashList)
	srcMatSigPath := filepath.Join(baseDir, interlaceConfig.SourceMaterialSignature)
	fmt.Println("[DEBUG] srcMatPath: ", srcMatPath)

	if _, err := os.Stat(srcMatPath); errors.Is(err, os.ErrNotExist) {
		return VerifyResult{Result: utils.VerifyResultInvalid, Message: fmt.Sprintf("%s does not exist in the repository", interlaceConfig.SourceMaterialHashList)}, nil
	}

	if _, err := os.Stat(srcMatSigPath); errors.Is(err, os.ErrNotExist) {
		return VerifyResult{Result: utils.VerifyResultInvalid, Message: fmt.Sprintf("%s does not exist in the repository", interlaceConfig.SourceMaterialSignature)}, nil
	}

	verification_target, err := os.Open(srcMatPath)
	if err != nil {
		return VerifyResult{}, errors.Wrap(err, fmt.Sprintf("error when opening the material hash file `%s`", srcMatPath))
	}
	signature, err := os.Open(srcMatSigPath)
	if err != nil {
		return VerifyResult{}, errors.Wrap(err, fmt.Sprintf("error when opening the signature file `%s`", srcMatSigPath))
	}
	sigOK, failReason, _, _, err := verifySignature(keyPath, verification_target, signature)
	if err != nil {
		return VerifyResult{}, errors.Wrap(err, "error in verifying signature")
	}
	if !sigOK {
		return VerifyResult{Result: utils.VerifyResultInvalid, Message: fmt.Sprintf("signature verification failed; %s", failReason)}, nil
	}

	hashOK, err := compareHash(srcMatPath, baseDir)
	if err != nil {
		return VerifyResult{}, err
	}
	if !hashOK {
		return VerifyResult{Result: utils.VerifyResultInvalid, Message: "hash does not match with the signed hash file"}, nil
	}

	return VerifyResult{Result: utils.VerifyResultValid, Message: "signature verification passed"}, nil
}

func (p *Provenance) GetReference() *provenance.ProvenanceRef {
	return p.ref
}

func verifySignature(keyPath string, msg, sig *os.File) (bool, string, *Signer, []byte, error) {

	if keyRing, err := LoadKeyRing(keyPath); err != nil {
		return false, "Error when loading key ring", nil, nil, err
	} else if signer, err := openpgp.CheckArmoredDetachedSignature(keyRing, msg, sig); signer == nil {
		if err != nil {
			log.Error("Signature verification error:", err.Error())
		}
		return false, "Signed by unauthrized subject (signer is not in public key), or invalid format signature", nil, nil, nil
	} else {
		idt := GetFirstIdentity(signer)
		fingerprint := ""
		if signer.PrimaryKey != nil {
			fingerprint = fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
		}
		return true, "", NewSignerFromUserId(idt.UserId), []byte(fingerprint), nil
	}
}

func GetFirstIdentity(signer *openpgp.Entity) *openpgp.Identity {
	for _, idt := range signer.Identities {
		return idt
	}
	return nil
}

type Signer struct {
	Email              string `json:"email,omitempty"`
	Name               string `json:"name,omitempty"`
	Comment            string `json:"comment,omitempty"`
	Uid                string `json:"uid,omitempty"`
	Country            string `json:"country,omitempty"`
	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
	Locality           string `json:"locality,omitempty"`
	Province           string `json:"province,omitempty"`
	StreetAddress      string `json:"streetAddress,omitempty"`
	PostalCode         string `json:"postalCode,omitempty"`
	CommonName         string `json:"commonName,omitempty"`
	SerialNumber       string `json:"serialNumber,omitempty"`
	Fingerprint        []byte `json:"finerprint"`
}

func NewSignerFromUserId(uid *packet.UserId) *Signer {
	return &Signer{
		Email:   uid.Email,
		Name:    uid.Name,
		Comment: uid.Comment,
	}
}

func LoadKeyRing(keyPath string) (openpgp.EntityList, error) {
	entities := []*openpgp.Entity{}
	kpath := filepath.Clean(keyPath)
	if keyRingReader, err := os.Open(kpath); err != nil {
		return nil, errors.Wrap(err, "Failed to open keyring")
	} else {
		tmpList, err := openpgp.ReadKeyRing(keyRingReader)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to read keyring")
		}
		for _, tmp := range tmpList {
			for _, id := range tmp.Identities {
				log.Info("identity name ", id.Name, " id.UserId.Name: ", id.UserId.Name, " id.UserId.Email:", id.UserId.Email)
			}
			entities = append(entities, tmp)
		}
	}
	return openpgp.EntityList(entities), nil
}

func compareHash(sourceMaterialPath string, baseDir string) (bool, error) {
	sourceMaterial, err := ioutil.ReadFile(sourceMaterialPath)

	if err != nil {
		log.Errorf("Error in reading sourceMaterialPath:  %s", err.Error())
		return false, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(sourceMaterial)))

	for scanner.Scan() {
		l := scanner.Text()

		data := strings.Split(l, " ")
		if len(data) > 2 {
			hash := data[0]
			path := data[2]

			absPath := filepath.Join(baseDir, "/", path)
			computedFileHash, err := utils.ComputeHash(absPath)
			log.Info("file: ", path, " hash:", hash, " absPath:", absPath, " computedFileHash: ", computedFileHash)
			if err != nil {
				return false, err
			}

			if hash != computedFileHash {
				return false, nil
			}
		} else {
			continue
		}
	}
	return true, nil
}

func generateMaterial(appName, appPath, appSourceRepoUrl, appSourceRevision, appSourceCommitSha string, provTrace string) []in_toto.ProvenanceMaterial {

	materials := []in_toto.ProvenanceMaterial{}

	materials = append(materials, in_toto.ProvenanceMaterial{
		URI: appSourceRepoUrl + ".git",
		Digest: in_toto.DigestSet{
			"commit":   string(appSourceCommitSha),
			"revision": appSourceRevision,
			"path":     appPath,
		},
	})

	appSourceRepoUrlFul := appSourceRepoUrl + ".git"
	materialsStr := gjson.Get(provTrace, "predicate.materials")

	for _, mat := range materialsStr.Array() {

		uri := gjson.Get(mat.String(), "uri").String()
		path := gjson.Get(mat.String(), "digest.path").String()
		revision := gjson.Get(mat.String(), "digest.revision").String()
		commit := gjson.Get(mat.String(), "digest.commit").String()

		if uri != appSourceRepoUrlFul {
			intoMat := in_toto.ProvenanceMaterial{
				URI: uri,
				Digest: in_toto.DigestSet{
					"commit":   commit,
					"revision": revision,
					"path":     path,
				},
			}
			materials = append(materials, intoMat)
		}
	}

	return materials
}

type VerifyResult struct {
	Result  string `json:"result"`
	Message string `json:"message"`
}

func VerifySourceMaterial(repoPath, repoURL, revision string) (VerifyResult, error) {
	appdata, err := application.NewApplicationData("", repoPath, "", "", repoURL, revision, "", "", "", false, []string{}, "", "", "")
	if err != nil {
		return VerifyResult{}, errors.Wrap(err, "failed to initialize Application Data")
	}
	prov, err := NewProvenance(*appdata)
	if err != nil {
		return VerifyResult{}, errors.Wrap(err, "failed to initialize Provenance")
	}
	return prov.VerifySourceMaterial()
}
