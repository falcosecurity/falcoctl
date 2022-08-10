// Copyright 2019-2022 The Falco Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !linux

package cmd

import (
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// NewInstallRule creates the `install rule` command
func NewInstallRuleCmd(options CommandOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "rule",
		DisableFlagsInUseLine: true,
		Short:                 "Install Falco rules",
		Long:                  `Use this command to install various Falco rules from configured repositories`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Fatal("this command only works on machines running a linux kernel")

			return nil
		},
	}

	return cmd
}
