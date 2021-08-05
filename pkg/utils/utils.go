package utils

import (
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

//GetClient returns a kubernetes client
func GetClient(configpath string, debug bool) (*kubernetes.Clientset, *rest.Config, error) {

	if configpath == "" {
		if debug {
			logrus.Info("Using Incluster configuration")
		}
		config, err := rest.InClusterConfig()
		if err != nil {
			logrus.Fatalf("Error occured while reading incluster kubeconfig:%v", err)
			return nil, nil, err
		}
		clientset, _ := kubernetes.NewForConfig(config)
		return clientset, config, nil
	}
	if debug {
		logrus.Infof(":%s", configpath)
	}
	config, err := clientcmd.BuildConfigFromFlags("", configpath)
	if err != nil {
		logrus.Fatalf("Error occured while reading kubeconfig:%v", err)
		return nil, nil, err
	}
	clientset, _ := kubernetes.NewForConfig(config)
	return clientset, config, nil
}
