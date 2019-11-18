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
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/kubernetes/factory"
	"github.com/kris-nova/logger"
	"k8s.io/api/apps/v1beta2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/rbac/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsv1beta2 "k8s.io/client-go/kubernetes/typed/apps/v1beta2"
	auditregistrationv1alpha1 "k8s.io/client-go/kubernetes/typed/auditregistration/v1alpha1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	rbacv1beta1 "k8s.io/client-go/kubernetes/typed/rbac/v1beta1"
	"k8s.io/utils/pointer"
)

// falcoInstaller is a data structure used to install Falco in Kubernetes
type falcoInstaller struct {
	coreClient        corev1.CoreV1Interface
	auditClient       auditregistrationv1alpha1.AuditregistrationV1alpha1Interface
	rbacClient        rbacv1beta1.RbacV1beta1Interface
	appsv1beta2Client appsv1beta2.AppsV1beta2Interface
	namespace         string
}

// FalcoInstaller ...
type FalcoInstaller interface {
	Install() error
	Delete() error
}

// NewFalcoInstaller creates a new Falco installer for Kubernetes
func NewFalcoInstaller(f factory.Factory) (FalcoInstaller, error) {
	i := &falcoInstaller{}
	restConfig, err := f.ToRESTConfig()
	if err != nil {
		logger.Critical("Fatal error: %v", err)
		return nil, err
	}
	i.coreClient, err = corev1.NewForConfig(restConfig)
	if err != nil {
		logger.Critical("Fatal error: %v", err)
		return nil, err
	}
	i.rbacClient, err = rbacv1beta1.NewForConfig(restConfig)
	if err != nil {
		logger.Critical("Fatal error: %v", err)
		return nil, err
	}
	i.appsv1beta2Client, err = appsv1beta2.NewForConfig(restConfig)
	if err != nil {
		logger.Critical("Fatal error: %v", err)
		return nil, err
	}
	i.auditClient, err = auditregistrationv1alpha1.NewForConfig(restConfig)
	if err != nil {
		logger.Critical("Fatal error: %v", err)
		return nil, err
	}
	i.namespace = "falco" // todo > inject

	return i, nil
}

// Delete is brute force method used to permanently destroy Falco resources in Kubernetes.
// todo > delete also service account, etc.
func (i *falcoInstaller) Delete() error {
	// Namespace
	err := i.coreClient.Namespaces().Delete(i.namespace, &metav1.DeleteOptions{})
	if err != nil {
		logger.Critical("Error deleting namespace: %v", err)
	} else {
		logger.Always("Falco namespace deleted: %s", i.namespace)
	}
	return nil
}

// Install is an idempotent installer for Falco in Kubernetes. By design if a resource already exists, we log it
// and move on with installing the others.
// Right now, the methods to obtain the Kubernetes resources are hard-coded here, but I (@kris-nova) think we should
// abstract the logic for how we acquire the description for our resources.
func (i *falcoInstaller) Install() error {
	// Namespace
	err := createNamespace(i.coreClient.Namespaces(), i.namespace)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			logger.Critical("Error creating namespace: %v", err)
		} else {
			logger.Info("Namespace already exists: %v", i.namespace)
		}
	} else {
		logger.Always("Falco namespace created: %s", i.namespace)
	}

	// RBAC
	serviceAccountName := "falco-sa" // todo > inject
	err = createRBAC(i.coreClient.ServiceAccounts(i.namespace), i.rbacClient.ClusterRoles(), i.rbacClient.ClusterRoleBindings(), serviceAccountName, i.namespace)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			logger.Critical("Error creating RBAC: %v", err)
		} else {
			logger.Info("RBAC already exists: %v", i.namespace)
		}
	} else {
		logger.Always("RBAC created: %s", i.namespace)
	}

	// ConfigMap
	configMapName := "falco-cm" // todo > inject
	err = createConfigMap(i.coreClient.ConfigMaps(i.namespace), configMapName, i.namespace)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			logger.Critical("Error creating ConfigMap: %v", err)
		} else {
			logger.Info("ConfigMap already exists: %v", i.namespace)
		}
	} else {
		logger.Always("ConfigMap created: %s", i.namespace)
	}
	// DaemonSet
	daemonSetName := "falco-ds" // todo > inject
	err = createDaemonSet(i.appsv1beta2Client.DaemonSets(i.namespace), serviceAccountName, configMapName, daemonSetName, false)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			logger.Critical("Error creating DaemonSet: %v", err)
		} else {
			logger.Info("DaemonSet already exists: %v", i.namespace)
		}
	} else {
		logger.Always("DaemonSet created: %s", i.namespace)
	}
	// Service
	serviceName := "falco-svc" // todo > inject
	err = createService(i.coreClient.Services(i.namespace), serviceName, i.namespace)
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			logger.Critical("Error creating Service: %v", err)
		} else {
			logger.Info("Service already exists: %v", i.namespace)
		}
	} else {
		logger.Always("Service created: %s", i.namespace)
	}
	return NewAuditInstaller(i.coreClient, i.auditClient, i.namespace, serviceAccountName).Install()
}

func createService(serviceClient corev1.ServiceInterface, serviceName string, namespace string) error {
	svc := &v1.Service{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceName,
			Namespace: namespace,
			Labels: map[string]string{
				"app":  "falco",
				"role": "security",
			},
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{
				{
					Port:     8765,
					Protocol: "TCP",
				},
			},
			Selector: map[string]string{
				"app": "falco",
			},
		},
		Status: v1.ServiceStatus{},
	}
	_, err := serviceClient.Create(svc)
	if err != nil {
		return err
	}
	return nil
}

func createRBAC(serviceAccountClient corev1.ServiceAccountInterface, clusterRoleClient rbacv1beta1.ClusterRoleInterface, clusterRoleBindingClient rbacv1beta1.ClusterRoleBindingInterface, serviceAccountName string, namespace string) error {
	sa := &v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceAccountName,
			Labels: map[string]string{
				"app":  "falco",
				"role": "security",
			},
		},
	}
	_, err := serviceAccountClient.Create(sa)
	if err != nil {
		return err
	}

	cr := &v1beta1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "falco-cluster-role",
			Labels: map[string]string{
				"app":  "falco",
				"role": "security",
			},
		},
		Rules: []v1beta1.PolicyRule{
			{
				APIGroups: []string{
					"extensions",
					"",
				},
				Resources: []string{
					"nodes",
					"namespaces",
					"pods",
					"replicationcontrollers",
					"replicasets",
					"services",
					"daemonsets",
					"deployments",
					"events",
					"configmaps",
				},
				Verbs: []string{
					"get",
					"list",
					"watch",
				},
			},
			{
				NonResourceURLs: []string{
					"/healthz",
					"/healthz/",
				},
				Verbs: []string{
					"get",
				},
			},
		},
	}
	_, err = clusterRoleClient.Create(cr)
	if err != nil {
		return err
	}

	crb := &v1beta1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "falco-cluster-role-binding",
			Namespace: namespace,
			Labels: map[string]string{
				"app":  "falco",
				"role": "security",
			},
		},
		Subjects: []v1beta1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      serviceAccountName,
				Namespace: namespace,
			},
		},
		RoleRef: v1beta1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "falco-cluster-role",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
	_, err = clusterRoleBindingClient.Create(crb)
	if err != nil {
		return err
	}
	return nil

}

func createConfigMap(configMapClient corev1.ConfigMapInterface, configMapName string, namespace string) error {
	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: namespace,
		},
		Data: defaultFalcoConfig,
	}
	_, err := configMapClient.Create(cm)
	if err != nil {
		return err
	}
	return nil
}

func createNamespace(namespaceClient corev1.NamespaceInterface, name string) error {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	_, err := namespaceClient.Create(ns)
	return err
}

func createDaemonSet(daemonSetClient appsv1beta2.DaemonSetInterface, serviceAccountName string, configMapName string, daemonSetName string, bpf bool) error {
	useBPF := "PASS"
	if bpf == true {
		useBPF = "SYSDIG_BPF_PROBE"
	}
	ds := &v1beta2.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: daemonSetName,
			Labels: map[string]string{
				"app":  "falco",
				"role": "security",
			},
		},
		Spec: v1beta2.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":  "falco",
					"role": "security",
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app":  "falco",
						"role": "security",
					},
				},
				Spec: v1.PodSpec{
					ServiceAccountName: serviceAccountName,
					Containers: []v1.Container{
						{
							Name:  "falco",
							Image: "falcosecurity/falco-slim:0.17.0", // TODO use a specific version not `latest`
							SecurityContext: &v1.SecurityContext{
								Privileged: pointer.BoolPtr(true),
							},
							Env: []v1.EnvVar{
								{
									Name:  useBPF,
									Value: "",
								},
								{
									Name:  "KUBERNETES_SERVICE_HOST",
									Value: "kubernetes.default.svc.cluster.local",
								},
								{
									Name:  "KUBERNETES_SERVICE_PORT",
									Value: "443",
								},
							},
							Args: []string{
								"/usr/bin/falco",
								"--cri",
								"/host/run/containerd/containerd.sock",
								"-K",
								"/var/run/secrets/kubernetes.io/serviceaccount/token",
								"-k",
								"https://kubernetes.default.svc.cluster.local",
								"-pk",
							},
							VolumeMounts: []v1.VolumeMount{
								{
									Name:      "docker-socket",
									MountPath: "/host/var/run/docker.sock",
								},
								{
									Name:      "containerd-socket",
									MountPath: "/host/run/containerd/containerd.sock",
								},
								{
									Name:      "dev-fs",
									MountPath: "/host/dev",
									// todo > read only?
								},
								{
									Name:      "proc-fs",
									MountPath: "/host/proc",
									ReadOnly:  true,
								},
								{
									Name:      "boot-fs",
									MountPath: "/host/boot",
									ReadOnly:  true,
								},
								{
									Name:      "lib-modules",
									MountPath: "/host/lib/modules",
									ReadOnly:  false,
								},
								{
									Name:      "usr-fs",
									MountPath: "/host/usr",
									ReadOnly:  true,
								},
								{
									Name:      "etc-fs",
									MountPath: "/host/etc",
									ReadOnly:  true,
								},
								{
									Name:      configMapName,
									MountPath: "/etc/falco",
								},
							},
						},
					},
					Volumes: []v1.Volume{
						{
							Name: "docker-socket",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/var/run/docker.sock",
								},
							},
						},
						{
							Name: "containerd-socket",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/run/containerd/containerd.sock",
								},
							},
						},
						{
							Name: "dev-fs",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/dev",
								},
							},
						},
						{
							Name: "proc-fs",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/proc",
								},
							},
						},
						{
							Name: "boot-fs",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/boot",
								},
							},
						},
						{
							Name: "lib-modules",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/lib/modules",
								},
							},
						},
						{
							Name: "usr-fs",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/usr",
								},
							},
						},
						{
							Name: "etc-fs",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/etc",
								},
							},
						},
						{
							Name: configMapName,
							VolumeSource: v1.VolumeSource{
								ConfigMap: &v1.ConfigMapVolumeSource{
									LocalObjectReference: v1.LocalObjectReference{Name: configMapName},
								},
							},
						},
					},
				},
			},
		},
	}
	_, err := daemonSetClient.Create(ds)
	if err != nil {
		return err
	}
	return nil
}
