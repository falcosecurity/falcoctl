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
package cmd

import (
	"fmt"
	"os"

	"path"

	kubernetesfalc "github.com/falcosecurity/falcoctl/kubernetes"
	"github.com/falcosecurity/falcoctl/pkg/cli"
	"github.com/kris-nova/logger"
	homedir "github.com/mitchellh/go-homedir"

	"github.com/spf13/cobra"
)

// deleteFalcoCmd represents the deleteFalco command
var (
	deleteFalcoCmd = &cobra.Command{
		Use:   "falco",
		Short: "Delete Falco from Kubernetes",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			err, exitCode := DeleteFalcoEntry(i, kubeConfigPath)
			if err != nil {
				logger.Critical("Fatal error: %v", err)
				os.Exit(exitCode)
			}
			logger.Always("Success.")
			///	os.Exit(1)		},
		},
	}
)

func init() {
	home, err := homedir.Dir()
	if err != nil {
		logger.Critical("Fatal error: %v", err)
		os.Exit(1)
	}
	deleteCmd.AddCommand(deleteFalcoCmd)
	installFalcoCmd.Flags().StringVarP(&kubeConfigPath, "kube-config-path", "k",
		cli.GetEnvWithDefault("FALCOCTL_KUBE_CONFIG_PATH", path.Join(home, ".kube/config")),
		"Set the path to the Kube config")
	installFalcoCmd.Flags().StringVarP(&i.NamespaceName, "namespace", "n",
		cli.GetEnvWithDefault("FALCOCTL_KUBE_NAMESPACE", "falco"), "Set the namespace to install Falco in")
}

func DeleteFalcoEntry(installer *kubernetesfalc.FalcoInstaller, kubeConfigPath string) (error, int) {
	k8s, err := kubernetesfalc.NewK8sFromKubeConfigPath(kubeConfigPath)
	if err != nil {
		return fmt.Errorf("unable to parse kube config: %v", err), 98
	}
	err = installer.Delete(k8s)
	if err != nil {
		return fmt.Errorf("unable to delete falco in Kubernetes: %v", err), 99
	}
	return nil, 0
}
