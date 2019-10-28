// +build !linux

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
	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// NewProbeInstallCommand creates the `install probe` command
func NewProbeInstallCommand(streams genericclioptions.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "probe",
		DisableFlagsInUseLine: true,
		Short:                 "Install the Falco probe locally (linux only)",
		Long:                  `Download and install the Falco module locally`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Critical("this command only works on machines running a linux kernel")

			return nil
		},
	}

	return cmd
}
