/*
Copyright © 2019 Kris Nova <kris@nivenly.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
