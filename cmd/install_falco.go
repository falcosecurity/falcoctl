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
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// NewInstallFalco creates the `install falco` command
func NewInstallFalcoCmd(options CommandOptions) *cobra.Command {

	cmd := &cobra.Command{
		Use:                   "falco",
		TraverseChildren:      true,
		DisableFlagsInUseLine: true,
		Short:                 "Install Falco in Kubernetes",
		Long:                  `Deploy Falco to Kubernetes`,
		Run: func(cmd *cobra.Command, args []string) {
			logger.Info("to be implemented")
		},
	}

	return cmd
}
