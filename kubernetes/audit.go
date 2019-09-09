package kubernetesfalc

import (
	"fmt"
	"strings"

	"k8s.io/api/auditregistration/v1alpha1"

	"github.com/kris-nova/logger"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	APIServerNamespace = "kube-system"
)

type AuditInstaller struct {
	k8s            *kubernetesConfigClient
	FalcoNamespace string
}

func (i *AuditInstaller) Install(k8s *kubernetesConfigClient) error {
	i.k8s = k8s
	logger.Info("Configuring Kubernetes Audit Logging")
	logger.Info("Searching for API server...")
	pods, err := k8s.client.CoreV1().Pods(APIServerNamespace).List(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to list pods in kube-system Namespace: %v", err)
	}
	var apiServer v1.Pod
	found := false
	for _, pod := range pods.Items {
		if strings.Contains(pod.Name, "kube-apiserver") {
			found = true
			logger.Success("Found API server...")
			apiServer = pod
			break
		}
	}
	if !found {
		return fmt.Errorf("unable to find kube-apiserver")
	}

	// -----------------------------------------------------------------------------------------------------------------
	//
	// Enable Audit Flags
	logger.Info("Setting new API server flags...")
	apiServer.Spec.Containers[0].Command = append(apiServer.Spec.Containers[0].Command,
		"--tls-private-key-file=/etc/kubernetes/pki/apiserver.key")
	apiServer.Spec.Containers[0].Command = append(apiServer.Spec.Containers[0].Command,
		"--feature-gates=DynamicAuditing=true")
	apiServer.Spec.Containers[0].Command = append(apiServer.Spec.Containers[0].Command,
		"--runtime-config=auditregistration.k8s.io/v1alpha1=true")

	//_, err = i.k8s.client.CoreV1().Pods(APIServerNamespace).Update(&apiServer)
	//if err != nil {
	//	return fmt.Errorf("unable to update API server: %v", err)
	//}

	// TODO - Generate YAML and patch the server manifest
	// TODO - Generate YAML and patch the server manifest
	// We have to replace the YAML via SSH - we CANNOT update the static pod.
	// The Kubelet is smart enough to restart the API server pod once the new configuration has been written.
	//
	// - Generate YAML from struct
	// - SSH / SCP the file to /etc/kubernetes
	// - Validate the AuditSink resource is available

	logger.Success("Successfully updated API server...")
	_, err = i, k8s.client.CoreV1().Pods(APIServerNamespace).Delete(apiServer.Name, &metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("unable to restart API server: %v", err)
	}
	logger.Success("Audit logging enabled")
	logger.Info("Configuring Falco as an audit endpoint")

	svc, err := i.k8s.client.CoreV1().Services(i.FalcoNamespace).Get("falco-service", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("Unable to find Falco service")
	}
	ip := svc.Spec.ClusterIP
	endpoint := fmt.Sprintf("http://%s:8765/k8s_audit", ip)
	as := v1alpha1.AuditSink{
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
					QPS:   i64(10),
					Burst: i64(15),
				},
				ClientConfig: v1alpha1.WebhookClientConfig{
					URL: &endpoint,
				},
			},
		},
	}

	_, err = i.k8s.client.AuditregistrationV1alpha1().AuditSinks().Create(&as)
	if err != nil {
		return fmt.Errorf("unable to instlal AuditSink: %v", err)
	}
	logger.Success("Kubernetes AuditSink enabled with Falco.")
	return nil
}

func i64(i int) *int64 {
	i64 := int64(i)
	return &i64
}
