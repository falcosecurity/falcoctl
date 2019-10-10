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

	"github.com/falcosecurity/falcoctl/pkg/cli"
	kubernetesfalc "github.com/falcosecurity/falcoctl/kubernetes"
	homedir "github.com/mitchellh/go-homedir"

	"github.com/kris-nova/logger"

	"github.com/spf13/cobra"
)

var fabulous bool

var (
	// Global for all install methods
	i              = &kubernetesfalc.FalcoInstaller{}
	kubeConfigPath string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "falcoctl",
	Short: "The main control tool for running Falco in Kubernetes",
	Long: `

`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	home, err := homedir.Dir()
	if err != nil {
		logger.Critical("Fatal error: %v", err)
		os.Exit(1)
	}
	rootCmd.Flags().IntVarP(&logger.Level, "verbose", "v", 4, "Verbosity for logs between 1(lowest) and 4(highest).")
	rootCmd.PersistentFlags().StringVarP(&kubeConfigPath, "kube-config-path", "k",
		cli.GetEnvWithDefault("FALCOCTL_KUBE_CONFIG_PATH", path.Join(home, ".kube/config")),
		"Set the path to the Kube config")
	rootCmd.PersistentFlags().StringVarP(&i.NamespaceName, "namespace", "n",
		cli.GetEnvWithDefault("FALCOCTL_KUBE_NAMESPACE", "falco"), "Set the namespace to install Falco in")
	rootCmd.PersistentFlags().BoolVarP(&fabulous, "fab", "f",
		cli.GetBoolEnvWithDefault("FALCOCTL_FABULOUS", false), "Enable rainbow logs.")
}
