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

package utils

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/argoproj-labs/argocd-interlace/pkg/config"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	MANIFEST_FILE_NAME           = "manifest.yaml"
	MANIFEST_DIR                 = "manifest-bundles"
	SIGNED_MANIFEST_FILE_NAME    = "manifest.signed"
	PROVENANCE_FILE_NAME         = "provenance.yaml"
	ATTESTATION_FILE_NAME        = "attestation.json"
	TMP_DIR                      = "/tmp/output"
	PRIVATE_KEY_PATH             = "/etc/signing-secrets/cosign.key"
	PUB_KEY_PATH                 = "/etc/signing-secrets/cosign.pub"
	KEYRING_PUB_KEY_PATH_ENV_VAR = "KEYRING_PUB_KEY_PATH"
	DEFAULT_KEYRING_PUB_KEY_PATH = "/.gnupg/pubring.gpg"
	SIG_ANNOTATION_NAME          = "cosign.sigstore.dev/signature"
	MSG_ANNOTATION_NAME          = "cosign.sigstore.dev/message"
	RETRY_ATTEMPTS               = 10
)

// Signature verification results
const (
	VerifyResultUnknown = ""
	VerifyResultValid   = "Valid"
	VerifyResultInvalid = "Invalid"
)

func SourceRepoVerificationEnabled() bool {
	// TODO: add switch
	return true
}

//GetClient returns a kubernetes client
func GetClient(configpath string) (*kubernetes.Clientset, *rest.Config, error) {

	if configpath == "" {
		log.Debug("Using Incluster configuration")

		config, err := rest.InClusterConfig()
		if err != nil {
			log.Errorf("Error occured while reading incluster kubeconfig %s", err.Error())
			return nil, nil, err
		}
		clientset, _ := kubernetes.NewForConfig(config)
		return clientset, config, nil
	}

	config, err := clientcmd.BuildConfigFromFlags("", configpath)
	if err != nil {
		log.Errorf("Error occured while reading kubeconfig %s ", err.Error())
		return nil, nil, err
	}
	clientset, _ := kubernetes.NewForConfig(config)
	return clientset, config, nil
}

func GetPubkeyPath() string {
	keypath := os.Getenv(KEYRING_PUB_KEY_PATH_ENV_VAR)
	if keypath != "" {
		return keypath
	}
	return DEFAULT_KEYRING_PUB_KEY_PATH
}

func WriteToFile(str, dirPath, filename string) error {

	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err := os.MkdirAll(dirPath, os.ModePerm)
		if err != nil {
			log.Errorf("Error occured while creating a dir %s ", err.Error())
			return err
		}
	}

	absFilePath := filepath.Join(dirPath, filename)

	f, err := os.Create(absFilePath)
	if err != nil {
		log.Errorf("Error occured while opening file %s ", err.Error())
		return err
	}

	defer f.Close()
	_, err = f.WriteString(str)
	if err != nil {
		log.Errorf("Error occured while writing to file %s ", err.Error())
		return err
	}

	return nil

}

func QueryAPI(url, requestType, bearerToken string, data map[string]interface{}) (string, error) {

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	bearer := ""
	if bearerToken != "" {
		bearer = "Bearer " + bearerToken
	}

	var dataJson []byte
	if data != nil {
		dataJson, _ = json.Marshal(data)
	} else {
		dataJson = nil
	}
	req, err := http.NewRequest(requestType, url, bytes.NewBuffer(dataJson))
	if err != nil {
		log.Errorf("Error %s ", err.Error())
		return "", err
	}

	if bearer != "" {
		req.Header.Add("Authorization", bearer)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Error %s", err.Error())
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error %s ", err.Error())
		return "", err
	}

	return string([]byte(body)), nil
}

func RetriveDesiredManifest(appName string) (string, error) {

	interlaceConfig, err := config.GetInterlaceConfig()
	if err != nil {
		log.Errorf("Error in loading config: %s", err.Error())
	}

	baseUrl := interlaceConfig.ArgocdApiBaseUrl

	desiredRscUrl := fmt.Sprintf("%s/%s/managed-resources", baseUrl, appName)

	token := interlaceConfig.ArgocdApiToken

	desiredManifest, err := QueryAPI(desiredRscUrl, "GET", token, nil)

	if err != nil {
		log.Errorf("Error occured while querying argocd REST API %s ", err.Error())
		return "", err
	}

	return desiredManifest, nil
}

func FileExist(fpath string) bool {
	if _, err := os.Stat(fpath); err == nil {
		return true
	}
	return false
}

func ComputeHash(filePath string) (string, error) {
	if FileExist(filePath) {
		f, err := os.Open(filePath)
		if err != nil {
			log.Info("Error in opening file !")
			return "", err
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			log.Info("Error in copying file !")
			return "", err
		}

		sum := h.Sum(nil)
		hashstring := fmt.Sprintf("%x", sum)
		return hashstring, nil
	}
	return "", fmt.Errorf("File not found ")
}

func CmdExec(baseCmd, dir string, args ...string) (string, error) {
	cmd := exec.Command(baseCmd, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if dir != "" {
		cmd.Dir = dir
	}
	err := cmd.Run()
	if err != nil {
		return "", errors.Wrap(err, stderr.String())
	}
	out := stdout.String()
	return out, nil
}
