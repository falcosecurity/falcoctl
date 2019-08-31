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

	kubernetesfalc "github.com/kris-nova/falcoctl/kubernetes"
	"github.com/kubicorn/kubicorn/pkg/cli"
	"github.com/kubicorn/kubicorn/pkg/local"
	"github.com/kubicorn/kubicorn/pkg/logger"

	"github.com/spf13/cobra"
)

var (
	installFalcoCmd = &cobra.Command{
		Use:   "falco",
		Short: "Install Falco in Kubernetes",
		Long:  `Deploy Falco to Kubernetes`,
		Run: func(cmd *cobra.Command, args []string) {
			err, exitCode := InstallFalcoEntry(i)
			if err != nil {
				logger.Critical("Fatal error: %v", err)
				os.Exit(exitCode)
			}
			logger.Always("Success.")
			os.Exit(1)
		},
	}
	i = &kubernetesfalc.FalcoInstaller{}
)

func InstallFalcoEntry(installer *kubernetesfalc.FalcoInstaller) (error, int) {
	err := installer.Install()
	if err != nil {
		return fmt.Errorf("unable to install falco in Kubernetes: %v", err), 99
	}
	return nil, 0
}

func init() {
	installFalcoCmd.Flags().StringVarP(&i.KubeConfigPath, "kube-config-path", "k", cli.StrEnvDef("FALCOCTL_KUBE_CONFIG_PATH", fmt.Sprintf("%s/.kube/config", local.Home())), "Set the path to the Kube config")
	installFalcoCmd.Flags().StringVarP(&i.Namespace, "namespace", "n", cli.StrEnvDef("FALCOCTL_KUBE_NAMESPACE", "default"), "Set the namespace to install Falco in")
}
