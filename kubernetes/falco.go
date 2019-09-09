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

	"github.com/kris-nova/logger"
	"k8s.io/api/apps/v1beta2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/api/rbac/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

// FalcoInstaller is a data structure used to install Falco in Kubernetes
type FalcoInstaller struct {
	k8s *kubernetesConfigClient

	// NamespaceName is an example of a "Global" variable we certainly should have
	NamespaceName string

	// DaemonSetName is an example of a "Possible" variable we don't know if we wan't to expose
	DameonSetName string
}

// Delete is brute force method used to permanently destroy Falco resources in Kubernetes.
func (i *FalcoInstaller) Delete(k8s *kubernetesConfigClient) error {
	i.k8s = k8s

	// -----------------------------------------------------------------------------------------------------------------
	//
	// Namespace
	err := i.k8s.client.CoreV1().Namespaces().Delete(i.NamespaceName, &metav1.DeleteOptions{})
	if err != nil {
		logger.Info("Delete Namespace: %v", err)
	} else {
		logger.Success("Delete Falco Namespace [%s]", i.NamespaceName)
	}

	return nil
}

// Install is an idempotent installer for Falco in Kubernetes. By design if a resource already exists, we log it
// and move on with installing the others.
// Right now, the methods to obtain the Kubernetes resources are hard-coded here, but I (@kris-nova) think we should
// abstract the logic for how we acquire the description for our resources.
func (i *FalcoInstaller) Install(k8s *kubernetesConfigClient) error {
	// Strong preference over keeping the Kubernetes client only available in this package, but still allowing an
	// outside package to use this based on logic from the unexported kubernetesConfigClient
	i.k8s = k8s

	// -----------------------------------------------------------------------------------------------------------------
	//
	// Namespace
	err := i.iNamespace()
	if err != nil {
		logger.Info("Create Namespace: %v", err)
	} else {
		logger.Success("Installed Falco Namespace [%s]", i.NamespaceName)
	}

	// -----------------------------------------------------------------------------------------------------------------
	//
	// Auth
	err = i.iFalcoRBAC()
	if err != nil {
		logger.Info("Create RBAC: %v", err)
	} else {
		logger.Success("Installed Falco RBAC")
	}

	// -----------------------------------------------------------------------------------------------------------------
	//
	// ConfigMap
	err = i.iConfigMap()
	if err != nil {
		logger.Info("Create ConfigMap: %v", err)
	} else {
		logger.Success("Installed Falco ConfigMap")
	}

	// -----------------------------------------------------------------------------------------------------------------
	//
	// DaemonSet
	err = i.iDaemonSet(false)
	if err != nil {
		logger.Info("Create Falco DaemonSet: %v", err)
	} else {
		logger.Success("Installed Falco DameonSet [%s]", i.DameonSetName)
	}

	// -----------------------------------------------------------------------------------------------------------------
	//
	// Service
	err = i.iFalcoService()
	if err != nil {
		logger.Info("Create Falco Service: %v", err)
	} else {
		logger.Success("Installed Falco Service [%s]", "falco-service")
	}

	audit := AuditInstaller{
		FalcoNamespace: i.NamespaceName,
	}
	return audit.Install(i.k8s)

}

func (i *FalcoInstaller) iFalcoService() error {
	svc := v1.Service{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "falco-service",
			Namespace: i.NamespaceName,
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
	_, err := i.k8s.client.CoreV1().Services(i.NamespaceName).Create(&svc)
	if err != nil {
		return fmt.Errorf("unable to create Falco service %v", err)
	}
	return nil
}

func (i *FalcoInstaller) iFalcoRBAC() error {
	sa := v1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name: "falco-account",
			Labels: map[string]string{
				"app":  "falco",
				"role": "security",
			},
		},
	}
	_, err := i.k8s.client.CoreV1().ServiceAccounts(i.NamespaceName).Create(&sa)
	if err != nil {
		return fmt.Errorf("unable to create service account: %v", err)
	}

	cr := v1beta1.ClusterRole{
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
	_, err = i.k8s.client.RbacV1beta1().ClusterRoles().Create(&cr)
	if err != nil {
		return fmt.Errorf("unable to create cluster role: %v", err)
	}
	crb := v1beta1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "falco-cluster-role-binding",
			Namespace: i.NamespaceName,
			Labels: map[string]string{
				"app":  "falco",
				"role": "security",
			},
		},
		Subjects: []v1beta1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "falco-account",
				Namespace: i.NamespaceName,
			},
		},
		RoleRef: v1beta1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "falco-cluster-role",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
	_, err = i.k8s.client.RbacV1beta1().ClusterRoleBindings().Create(&crb)
	if err != nil {
		return fmt.Errorf("unable to install cluster role binding: %v", err)
	}
	return nil

}

func (i *FalcoInstaller) iConfigMap() error {
	cm := v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "falco-config",
			Namespace: i.NamespaceName,
		},
		Data: defaultFalcoConfig, // see installFalcoDefaultConfig.go
	}
	_, err := i.k8s.client.CoreV1().ConfigMaps(i.NamespaceName).Create(&cm)
	if err != nil {
		return fmt.Errorf("error insalling configmap: %v", err)
	}
	return nil
}

func (i *FalcoInstaller) iNamespace() error {
	ns := v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: i.NamespaceName,
		},
	}
	_, err := i.k8s.client.CoreV1().Namespaces().Create(&ns)
	if err != nil {
		return fmt.Errorf("unable to ensure namespace: %v", err)
	}

	return nil
}

func iDaemonSetWithBPF() {

}

func (i *FalcoInstaller) iDaemonSet(useBPF bool) error {
	t := true
	useBPFStr := "PASS"
	if useBPF == true {
		useBPFStr = "SYSDIG_BPF_PROBE"
	}
	ds := v1beta2.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: "falco-daemonset",
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
					ServiceAccountName: "falco-account",
					Containers: []v1.Container{
						{
							Name:  "falco",
							Image: "falcosecurity/falco-slim:0.17.0", // TODO use a specific version not `latest`
							SecurityContext: &v1.SecurityContext{
								Privileged: &t,
							},
							Env: []v1.EnvVar{
								{
									Name:  useBPFStr,
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
									Name:      "falco-config",
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
							Name: "falco-config",
							VolumeSource: v1.VolumeSource{
								ConfigMap: &v1.ConfigMapVolumeSource{
									LocalObjectReference: v1.LocalObjectReference{Name: "falco-config"},
								},
							},
						},
					},
				},
			},
		},
	}
	//fmt.Printf("%+v\n", ds)
	_, err := i.k8s.client.AppsV1beta2().DaemonSets(i.NamespaceName).Create(&ds)
	if err != nil {
		return fmt.Errorf("error with client-go: %v", err)
	}
	return nil
}
