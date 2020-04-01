/*
Copyright © 2019 The Falco Authors.

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
	"strings"

	"github.com/kris-nova/logger"
	"k8s.io/api/auditregistration/v1alpha1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditregistrationv1alpha1 "k8s.io/client-go/kubernetes/typed/auditregistration/v1alpha1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/utils/pointer"
)

const (
	// APIServerNamespace ...
	APIServerNamespace = "kube-system"
)

type auditInstaller struct {
	coreClient         corev1.CoreV1Interface
	auditClient        auditregistrationv1alpha1.AuditregistrationV1alpha1Interface
	namespace          string
	serviceAccountName string
}

// NewAuditInstaller ...
func NewAuditInstaller(coreClient corev1.CoreV1Interface, auditClient auditregistrationv1alpha1.AuditregistrationV1alpha1Interface, namespace string, serviceAccountName string) *auditInstaller {
	logger.Info("New installer in namespace: %s", namespace)
	return &auditInstaller{
		coreClient:         coreClient,
		namespace:          namespace,
		serviceAccountName: serviceAccountName,
		auditClient:        auditClient,
	}
}

// Install ...
func (i *auditInstaller) Install() error {
	logger.Always("Configuring Kubernetes Audit Logging")
	logger.Always("Searching for API server...")
	pods, err := i.coreClient.Pods(APIServerNamespace).List(metav1.ListOptions{})
	if err != nil {
		return err
	}
	var apiServer v1.Pod
	found := false
	for _, pod := range pods.Items {
		if strings.Contains(pod.Name, "kube-apiserver") {
			found = true
			logger.Always("Found API server...")
			apiServer = pod
			break
		}
	}
	if !found {
		return fmt.Errorf("Unable to find kube-apiserver")
	}

	//// Enable audit flags
	//logger.Always("Setting new API server flags...")
	//apiServer.Spec.Containers[0].Command = append(
	//	apiServer.Spec.Containers[0].Command,
	//	"--tls-private-key-file=/etc/kubernetes/pki/apiserver.key",
	//)
	//apiServer.Spec.Containers[0].Command = append(
	//	apiServer.Spec.Containers[0].Command,
	//	"--feature-gates=DynamicAuditing=true",
	//)
	//apiServer.Spec.Containers[0].Command = append(
	//	apiServer.Spec.Containers[0].Command,
	//	"--runtime-config=auditregistration.k8s.io/v1alpha1=true",
	//)
	//
	//_, err = i.coreClient.Pods(APIServerNamespace).Update(&apiServer)
	//if err != nil {
	//	return fmt.Errorf("unable to update API server: %v", err)
	//}

	// TODO - Generate YAML and patch the server manifest
	// We have to replace the YAML via SSH - we CANNOT update the static pod.
	// The Kubelet is smart enough to restart the API server pod once the new configuration has been written.
	//
	// - Generate YAML from struct
	// - SSH / SCP the file to /etc/kubernetes
	// - Validate the AuditSink resource is available

	logger.Always("Successfully updated API server...")
	err = i.coreClient.Pods(APIServerNamespace).Delete(apiServer.Name, &metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("unable to restart API server: %v", err)
	}
	logger.Always("Audit logging enabled")
	logger.Always("Configuring Falco as an audit endpoint")

	svc, err := i.coreClient.Services(i.namespace).Get("falco-svc", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Unable to find Falco service: %s", i.namespace)
	}
	ip := svc.Spec.ClusterIP
	endpoint := fmt.Sprintf("http://%s:8765/k8s_audit", ip)
	as := &v1alpha1.AuditSink{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: "falco-audit-sink",
		},
		Spec: v1alpha1.AuditSinkSpec{
			Policy: v1alpha1.Policy{
				Level: "RequestResponse",
				Stages: []v1alpha1.Stage{
					"ResponseComplete",
					"ResponseStarted",
				},
			},
			Webhook: v1alpha1.Webhook{
				Throttle: &v1alpha1.WebhookThrottleConfig{
					QPS:   pointer.Int64Ptr(10),
					Burst: pointer.Int64Ptr(15),
				},
				ClientConfig: v1alpha1.WebhookClientConfig{
					URL: &endpoint,
				},
			},
		},
	}

	createOrUpdateAuditSink(i.auditClient, as)
	logger.Always("Kubernetes AuditSink enabled with Falco.")

	return nil
}

func createOrUpdateAuditSink(auditClient auditregistrationv1alpha1.AuditregistrationV1alpha1Interface, as *v1alpha1.AuditSink) error {
	_, err := auditClient.AuditSinks().Create(as)

	if err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("unable to create auditsink: %s", err)
		}

		logger.Info("AuditSink already exists: %v, updating existing AuditSink", as.Name)
		_, err := auditClient.AuditSinks().Update(as)
		if err != nil {
			return fmt.Errorf("unable to update auditsink: %s", err)
		}
	}

	return nil
}
