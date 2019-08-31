package kubernetesfalc

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type kubernetesConfigClient struct {
	config *rest.Config
	client *kubernetes.Clientset
}

func NewK8sFromKubeConfigPath(path string) (*kubernetesConfigClient, error) {
	config, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, fmt.Errorf("unable to load kube config: %v", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("unable to build Kubernetes client: %v", err)
	}
	return &kubernetesConfigClient{
		config: config,
		client: client,
	}, nil
}
