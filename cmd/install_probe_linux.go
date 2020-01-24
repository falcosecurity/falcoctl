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

	"github.com/falcosecurity/falcoctl/pkg/probeloader"
	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// ProbeOptions represents the `install probe` command options
type ProbeOptions struct {
	genericclioptions.IOStreams
	falcoVersion   string
	falcoProbePath string
	falcoProbeFile string
	falcoProbeURL  string
	falcoProbeRepo string
}

// Validate validates the `install probe` command options
func (o ProbeOptions) Validate(c *cobra.Command, args []string) error {
	if len(o.falcoVersion) == 0 {
		return fmt.Errorf("missing Falco version: specify it via FALCOCTL_FALCO_VERSION env variable or via --falco-version flag")
	}
	return nil
}

// NewProbeOptions instantiates the `install probe` command options
func NewProbeOptions(streams genericclioptions.IOStreams) CommandOptions {
	o := &ProbeOptions{
		IOStreams: streams,
	}
	o.falcoVersion = viper.GetString("falco-version")      // FALCOCTL_FALCO_VERSION env var
	o.falcoProbePath = viper.GetString("falco-probe-path") // FALCOCTL_FALCO_PROBE_PATH env var
	if len(o.falcoProbePath) == 0 {
		o.falcoProbePath = "/" // default
	}
	o.falcoProbeFile = viper.GetString("falco-probe-file") // FALCOCTL_FALCO_PROBE_FILE env var
	if len(o.falcoProbeFile) == 0 {
		o.falcoProbeFile = "falco-probe.ko" // default
	}
	o.falcoProbeURL = viper.GetString("falco-probe-url")   // FALCOCTL_FALCO_PROBE_URL env var
	o.falcoProbeRepo = viper.GetString("falco-probe-repo") // FALCOCTL_FALCO_PROBE_REPO env var
	if len(o.falcoProbeRepo) == 0 {
		o.falcoProbeRepo = "https://s3.amazonaws.com/download.draios.com/stable/sysdig-probe-binaries/" // default
	}
	return o
}

// InstallProbe creates the `install probe` command
func InstallProbe(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewProbeOptions(streams).(*ProbeOptions)

	cmd := &cobra.Command{
		Use:                   "probe",
		DisableFlagsInUseLine: true,
		Short:                 "Install the Falco probe locally",
		Long:                  `Download and install the Falco module locally`,
		PreRun: func(cmd *cobra.Command, args []string) {
			if err := o.Validate(cmd, args); err != nil {
				logger.Critical("%s", err)
				os.Exit(1)
			}
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			falcoProbeFullpath := path.Join(o.falcoProbePath, o.falcoProbeFile)
			falcoConfigHash, err := probeloader.GetKernelConfigHash()
			if err != nil {
				logger.Critical("Error getting Kernel Config Hash: %s", err)
				return err
			}
			falcoKernelRelease, err := probeloader.GetKernelRelease()
			if err != nil {
				logger.Critical("Error getting Kernel Version: %s", err)
				return err
			}

			logger.Always("FALCO_VERSION: %s", o.falcoVersion)
			logger.Always("FALCO_PROBE_URL: %s", o.falcoProbeURL)
			logger.Always("FALCO_PROBE_REPO: %s", o.falcoProbeRepo)
			logger.Always("KERNEL_VERSION: %s", falcoKernelRelease)
			logger.Always("KERNEL_CONFIG_HASH: %s", falcoConfigHash)

			// if FALCO_PROBE_URL not set, build it
			if o.falcoProbeURL == "" {
				o.falcoProbeURL = fmt.Sprintf("%sfalco-probe-%s-x86_64-%s-%s.ko", o.falcoProbeRepo, o.falcoVersion, falcoKernelRelease, falcoConfigHash)
			}

			// fetch module
			err = probeloader.FetchModule(o.falcoProbeURL, falcoProbeFullpath)
			if err != nil {
				logger.Critical("Error fetching module: %s", err)
				return err
			}

			// load module
			// TODO(ducy): Need to implement removal of module, retry loop, and timeout
			err = probeloader.LoadModule(falcoProbeFullpath)
			if err != nil {
				logger.Critical("Error loading module: %s", err)
				return err
			}

			return nil
		},
	}

	// TODO(fntlnz, leodido): validation
	cmd.Flags().StringVar(&o.falcoVersion, "falco-version", o.falcoVersion, "The falco version for which to download the probe")
	cmd.Flags().StringVar(&o.falcoProbePath, "falco-probe-path", o.falcoProbePath, "The path where to download the falco probe")
	cmd.Flags().StringVar(&o.falcoProbeFile, "falco-probe-file", o.falcoProbeFile, "The name of the falco probe file")
	cmd.Flags().StringVar(&o.falcoProbeURL, "falco-probe-url", o.falcoProbeURL, "The direct URL where to download the falco probe from, alternative to the repo, not the default, this skips the search since a direct url is provided")
	cmd.Flags().StringVar(&o.falcoProbeRepo, "falco-probe-repo", o.falcoProbeRepo, "The URL of the s3 repo where to search for the probe")
	return cmd
}
