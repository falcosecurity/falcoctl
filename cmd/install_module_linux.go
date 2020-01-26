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

package cmd

import (
	"fmt"
	"os"
	"path"

	"github.com/falcosecurity/falcoctl/pkg/kernelmoduleloader"
	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// ModuleOptions represents the `install module` command options
type ModuleOptions struct {
	genericclioptions.IOStreams
	falcoVersion    string
	falcoModulePath string
	falcoModuleFile string
	falcoModuleURL  string
	falcoModuleRepo string
}

// Validate validates the `install module` command options
func (o ModuleOptions) Validate(c *cobra.Command, args []string) error {
	if len(o.falcoVersion) == 0 {
		return fmt.Errorf("missing Falco version: specify it via FALCOCTL_FALCO_VERSION env variable or via --falco-version flag")
	}
	return nil
}

// NewModuleOptions instantiates the `install module` command options
func NewModuleOptions(streams genericclioptions.IOStreams) CommandOptions {
	o := &ModuleOptions{
		IOStreams: streams,
	}
	o.falcoVersion = viper.GetString("falco-version")        // FALCOCTL_FALCO_VERSION env var
	o.falcoModulePath = viper.GetString("falco-module-path") // FALCOCTL_FALCO_MODULE_PATH env var
	if len(o.falcoModulePath) == 0 {
		o.falcoModulePath = "/" // default
	}
	o.falcoModuleFile = viper.GetString("falco-module-file") // FALCOCTL_FALCO_MODULE_FILE env var
	if len(o.falcoModuleFile) == 0 {
		o.falcoModuleFile = "falco-module.ko" // default
	}
	o.falcoModuleURL = viper.GetString("falco-module-url")   // FALCOCTL_FALCO_MODULE_URL env var
	o.falcoModuleRepo = viper.GetString("falco-module-repo") // FALCOCTL_FALCO_MODULE_REPO env var
	if len(o.falcoModuleRepo) == 0 {
		o.falcoModuleRepo = "https://s3.amazonaws.com/download.draios.com/stable/sysdig-module-binaries/" // default
	}
	return o
}

// InstallModule creates the `install module` command
func InstallModule(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewModuleOptions(streams).(*ModuleOptions)

	cmd := &cobra.Command{
		Use:                   "module",
		DisableFlagsInUseLine: true,
		Short:                 "Install the Falco module locally",
		Long:                  `Download and install the Falco module locally`,
		PreRun: func(cmd *cobra.Command, args []string) {
			if err := o.Validate(cmd, args); err != nil {
				logger.Critical("%s", err)
				os.Exit(1)
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			falcoModuleFullpath := path.Join(o.falcoModulePath, o.falcoModuleFile)
			falcoConfigHash, err := kernelmoduleloader.GetKernelConfigHash()
			if err != nil {
				logger.Critical("Error getting Kernel Config Hash: %s", err)
				return err
			}
			falcoKernelRelease, err := kernelmoduleloader.GetKernelRelease()
			if err != nil {
				logger.Critical("Error getting Kernel Version: %s", err)
				return err
			}

			logger.Always("FALCO_VERSION: %s", o.falcoVersion)
			logger.Always("FALCO_MODULE_URL: %s", o.falcoModuleURL)
			logger.Always("FALCO_MODULE_REPO: %s", o.falcoModuleRepo)
			logger.Always("KERNEL_VERSION: %s", falcoKernelRelease)
			logger.Always("KERNEL_CONFIG_HASH: %s", falcoConfigHash)

			// if FALCO_MODULE_URL not set, build it
			if o.falcoModuleURL == "" {
				o.falcoModuleURL = fmt.Sprintf("%sfalco-module-%s-x86_64-%s-%s.ko", o.falcoModuleRepo, o.falcoVersion, falcoKernelRelease, falcoConfigHash)
			}

			// fetch module
			err = kernelmoduleloader.FetchModule(o.falcoModuleURL, falcoModuleFullpath)
			if err != nil {
				logger.Critical("Error fetching module: %s", err)
				return err
			}

			// load module
			// TODO(ducy): Need to implement removal of module, retry loop, and timeout
			err = kernelmoduleloader.LoadModule(falcoModuleFullpath)
			if err != nil {
				logger.Critical("Error loading module: %s", err)
				return err
			}

			return nil
		},
	}

	// TODO(fntlnz, leodido): validation
	cmd.Flags().StringVar(&o.falcoVersion, "falco-version", o.falcoVersion, "The falco version for which to download the module")
	cmd.Flags().StringVar(&o.falcoModulePath, "falco-module-path", o.falcoModulePath, "The path where to download the falco module")
	cmd.Flags().StringVar(&o.falcoModuleFile, "falco-module-file", o.falcoModuleFile, "The name of the falco module file")
	cmd.Flags().StringVar(&o.falcoModuleURL, "falco-module-url", o.falcoModuleURL, "The direct URL where to download the falco module from, alternative to the repo, not the default, this skips the search since a direct url is provided")
	cmd.Flags().StringVar(&o.falcoModuleRepo, "falco-module-repo", o.falcoModuleRepo, "The URL of the s3 repo where to search for the module")
	return cmd
}
