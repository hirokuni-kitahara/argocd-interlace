package utils

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

//GetClient returns a kubernetes client
func GetClient(configpath string) (*kubernetes.Clientset, *rest.Config, error) {

	if configpath == "" {
		log.Debug("Using Incluster configuration")

		config, err := rest.InClusterConfig()
		if err != nil {
			log.Fatal("Error occured while reading incluster kubeconfig:%v", err)
			return nil, nil, err
		}
		clientset, _ := kubernetes.NewForConfig(config)
		return clientset, config, nil
	}

	log.Debug(":%s", configpath)
	config, err := clientcmd.BuildConfigFromFlags("", configpath)
	if err != nil {
		log.Fatalf("Error occured while reading kubeconfig:%v", err)
		return nil, nil, err
	}
	clientset, _ := kubernetes.NewForConfig(config)
	return clientset, config, nil
}

func WriteToFile(str string, filename string) {

	f, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error occured while opening file %s :%v", filename, err)
	}

	defer f.Close()
	_, err = f.WriteString(str)
	if err != nil {
		log.Fatalf("Error occured while writing to file %s :%v", filename, err)
	}

}

func QueryAPI(url string, data map[string]string) string {

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
		log.Info("Error %s ", err)
	}

	req.Header.Add("Authorization", bearer)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Info("Error %s ", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Info("Error %s ", err)
	}

	return string([]byte(body))
}
