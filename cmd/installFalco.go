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

	kubernetesfalc "github.com/falcosecurity/falcoctl/kubernetes"
	"github.com/kris-nova/logger"
	"github.com/kubicorn/kubicorn/pkg/cli"
	"github.com/spf13/cobra"
)

var (
	installFalcoCmd = &cobra.Command{
		Use:   "falco",
		Short: "Install Falco in Kubernetes",
		Long:  `Deploy Falco to Kubernetes`,
		Run: func(cmd *cobra.Command, args []string) {

			err, exitCode := InstallFalcoEntry(i, kubeConfigPath)
			if err != nil {
				logger.Critical("Fatal error: %v", err)
				os.Exit(exitCode)
			}
			logger.Always("Success.")
			///	os.Exit(1)
		},
	}
)

// InstallFalcoEntry is used as the main entry point that someone who wants to test or vendor the code should use.
// This is the same starting place the CLI tool uses.
func InstallFalcoEntry(installer *kubernetesfalc.FalcoInstaller, kubeConfigPath string) (error, int) {
	k8s, err := kubernetesfalc.NewK8sFromKubeConfigPath(kubeConfigPath)
	if err != nil {
		return fmt.Errorf("unable to parse kube config: %v", err), 98
	}
	err = installer.Install(k8s)
	if err != nil {
		return fmt.Errorf("unable to install falco in Kubernetes: %v", err), 99
	}
	return nil, 0
}

func init() {
	installFalcoCmd.Flags().StringVarP(&i.DameonSetName, "ds-name", "N",
		cli.StrEnvDef("FALCOCTL_KUBE_DS_NAME", "falco"), "Set the name to use with the Falco DS")

}
