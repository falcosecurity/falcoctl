package kubernetesfalc

import (
	"fmt"

	"k8s.io/client-go/kubernetes"

	v1 "k8s.io/api/core/v1"

	"k8s.io/api/apps/v1beta2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/rest"

	"k8s.io/client-go/tools/clientcmd"

	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
)

type FalcoInstaller struct {
	config         *rest.Config
	client         *kubernetes.Clientset
	Namespace      string
	KubeConfigPath string
}

func (i *FalcoInstaller) Install() error {

	// create kubernetes clientset. this clientset can be used to create,delete,patch,list etc for the kubernetes resources
	config, err := clientcmd.BuildConfigFromFlags("", i.KubeConfigPath)
	if err != nil {
		fmt.Errorf("unable to load kube config: %v", err)
	}
	i.config = config
	client, err := kubernetes.NewForConfig(i.config)
	if err != nil {
		return fmt.Errorf("unable to build Kubernetes client: %v", err)
	}
	i.client = client

	err = i.FalcoDaemonSet(false)
	if err != nil {
		return fmt.Errorf("unable to install Falco DaemonSet: %", err)
	}

	return nil
}

func (i *FalcoInstaller) FalcoDaemonSet(useBPF bool) error {
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
							Name:            "falco",
							Image:           "falcosecurity/falco:latest", // TODO use a specific version not `latest`
							SecurityContext: &v1.SecurityContext{
								//Capabilities:             nil,
								//Privileged: &bool(true),
								//SELinuxOptions:           nil,
								//RunAsUser:                nil,
								//RunAsNonRoot:             nil,
								//ReadOnlyRootFilesystem:   nil,
								//AllowPrivilegeEscalation: nil,
							},
							Env: []v1.EnvVar{
								{
									Name:  useBPFStr,
									Value: "",
								},
							},
							Args: []string{
								"/usr/bin/falco",
								"--cri",
								"/host/run/containerd/containerd.sock",
								"-K",
								"/var/run/secrets/kubernetes.io/serviceaccount/token",
								"-k",
								"https://${KUBERNETES_SERVICE_HOST}",
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
									ReadOnly:  true,
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
									Path: "/proc",
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
									LocalObjectReference: v1.LocalObjectReference{Name: "falco-conf"},
								},
							},
						},
					},
				},
			},
		},
	}
	//fmt.Printf("%+v\n", ds)
	_, err := i.client.AppsV1beta2().DaemonSets(i.Namespace).Create(&ds)
	if err != nil {
		return fmt.Errorf("error with client-go: %v", err)
	}
	return nil
}
