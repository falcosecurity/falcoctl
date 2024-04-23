// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 The Falco Authors
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

package cmd_test

import (
	"context"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/cmd"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

var usageLinux = `
     __       _                _   _ 
    / _| __ _| | ___ ___   ___| |_| |
   | |_ / _  | |/ __/ _ \ / __| __| |
   |  _| (_| | | (_| (_) | (__| |_| |
   |_|  \__,_|_|\___\___/ \___|\__|_|
									 
	
The official CLI tool for working with Falco and its ecosystem components

Usage:
  falcoctl [command]

Available Commands:
  artifact    Interact with Falco artifacts
  completion  Generate the autocompletion script for the specified shell
  driver      Interact with falcosecurity driver
  help        Help about any command
  index       Interact with index
  registry    Interact with OCI registries
  tls         Generate and install TLS material for Falco
  version     Print the falcoctl version information

Flags:
      --config string       config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
  -h, --help                help for falcoctl
      --log-format string   Set formatting for logs (color, text, json) (default "color")
      --log-level string    Set level for logs (info, warn, debug, trace) (default "info")

Use "falcoctl [command] --help" for more information about a command.
`

var usageOthers = `
     __       _                _   _ 
    / _| __ _| | ___ ___   ___| |_| |
   | |_ / _  | |/ __/ _ \ / __| __| |
   |  _| (_| | | (_| (_) | (__| |_| |
   |_|  \__,_|_|\___\___/ \___|\__|_|
									 
	
The official CLI tool for working with Falco and its ecosystem components

Usage:
  falcoctl [command]

Available Commands:
  artifact    Interact with Falco artifacts
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  index       Interact with index
  registry    Interact with OCI registries
  tls         Generate and install TLS material for Falco
  version     Print the falcoctl version information

Flags:
      --config string       config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
  -h, --help                help for falcoctl
      --log-format string   Set formatting for logs (color, text, json) (default "color")
      --log-level string    Set level for logs (info, warn, debug, trace) (default "info")

Use "falcoctl [command] --help" for more information about a command.
`

func getUsage() string {
	if runtime.GOOS == "linux" {
		return usageLinux
	}
	return usageOthers
}

var _ = Describe("Root", func() {
	var (
		rootCmd   *cobra.Command
		ctx       = context.Background()
		opt       = commonoptions.NewOptions()
		err       error
		outputBuf = gbytes.NewBuffer()
		args      []string
	)

	JustBeforeEach(func() {
		// Each test creates a new root command, configures, and executes it.
		opt.Initialize(commonoptions.WithWriter(outputBuf))
		rootCmd = cmd.New(ctx, opt)
		rootCmd.SetOut(outputBuf)
		rootCmd.SetErr(outputBuf)
		rootCmd.SetArgs(args)
		err = cmd.Execute(rootCmd, opt)
	})

	JustAfterEach(func() {
		// Reset the output buffer.
		Expect(outputBuf.Clear()).ShouldNot(HaveOccurred())
		// Reset the arguments
		args = nil
	})

	Describe("Without args and without flags", func() {
		BeforeEach(func() {
			// Set args to an empty slice.
			args = []string{}
		})

		It("Should print the usage message", func() {
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(outputBuf.Contents())).Should(Equal(getUsage()))
		})
	})

	Describe("help argument", func() {
		BeforeEach(func() {
			// Set the help argument.
			args = []string{"help"}
		})

		It("Should print the usage message", func() {
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(outputBuf.Contents())).Should(Equal(getUsage()))
		})
	})

	Describe("help flag", func() {
		BeforeEach(func() {
			// Set the help argument.
			args = []string{"--help"}
		})

		It("Should print the usage message", func() {
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(outputBuf.Contents())).Should(Equal(getUsage()))
		})
	})

	Describe("wrong flag", func() {
		BeforeEach(func() {
			// Set the help argument.
			args = []string{"--wrong-flag"}
		})

		It("Should error and print the error", func() {
			Expect(err).Should(HaveOccurred())
			Expect(outputBuf).Should(gbytes.Say("ERROR unknown flag: --wrong-flag"))
		})
	})
})
