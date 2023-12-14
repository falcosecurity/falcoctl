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

package driverprintenv_test

import (
	"bufio"
	"os"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"

	"github.com/falcosecurity/falcoctl/cmd"
)

var driverPrintenvHelp = `[Preview] Print variables used by driver as env vars.
** This command is in preview and under development. **

Usage:
  falcoctl driver printenv [flags]

Flags:
  -h, --help   help for printenv

Global Flags:
      --config string       config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --host-root string    Driver host root to be used. (default "/")
      --log-format string   Set formatting for logs (color, text, json) (default "color")
      --log-level string    Set level for logs (info, warn, debug, trace) (default "info")
      --name string         Driver name to be used. (default "falco")
      --repo strings        Driver repo to be used. (default [https://download.falco.org/driver])
      --type string         Driver type to be used (auto, ebpf, kmod, modern_ebpf) (default "kmod")
      --version string      Driver version to be used.
`

var driverPrintenvDefaultConfig = `DRIVER="kmod"
DRIVERS_REPO="https:\/\/download\.falco\.org\/driver"
DRIVER_VERSION="1.0.0\+driver"
DRIVER_NAME="falco"
HOST_ROOT="\/"
TARGET_ID=".*"
ARCH="x86_64|aarch64"
KERNEL_RELEASE=".*"
KERNEL_VERSION=".*"
FIXED_KERNEL_RELEASE=".*"
FIXED_KERNEL_VERSION=".*"
`

var addAssertFailedBehavior = func(specificError string) {
	It("check that fails and the usage is not printed", func() {
		Expect(err).To(HaveOccurred())
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
	})
}

var _ = Describe("printenv", func() {

	var (
		driverCmd   = "driver"
		printenvCmd = "printenv"
	)

	// Each test gets its own root command and runs it.
	// The err variable is asserted by each test.
	JustBeforeEach(func() {
		rootCmd = cmd.New(ctx, opt)
		err = executeRoot(args)
	})

	JustAfterEach(func() {
		Expect(output.Clear()).ShouldNot(HaveOccurred())
	})

	Context("help message", func() {
		BeforeEach(func() {
			args = []string{driverCmd, printenvCmd, "--help"}
		})

		It("should match the saved one", func() {
			Expect(output).Should(gbytes.Say(regexp.QuoteMeta(driverPrintenvHelp)))
		})
	})

	// Here we are testing failure cases for cleaning a driver.
	Context("failure", func() {
		When("with empty driver version", func() {
			BeforeEach(func() {
				args = []string{driverCmd, printenvCmd, "--config", configFile}
			})
			addAssertFailedBehavior(`ERROR version is mandatory and cannot be empty `)
		})

		When("with non absolute host-root", func() {
			BeforeEach(func() {
				args = []string{driverCmd, printenvCmd, "--config", configFile, "--host-root", "foo/", "--version", "1.0.0+driver"}
			})
			addAssertFailedBehavior("ERROR host-root must be an absolute path (foo/)")
		})

		When("with invalid driver type", func() {
			BeforeEach(func() {
				args = []string{driverCmd, printenvCmd, "--config", configFile, "--type", "foo", "--version", "1.0.0+driver"}
			})
			addAssertFailedBehavior(`ERROR invalid argument "foo" for "--type" flag: invalid argument "foo",` +
				` please provide one of (auto, ebpf, kmod, modern_ebpf)`)
		})
	})

	Context("success", func() {
		When("with default config values", func() {
			BeforeEach(func() {
				args = []string{driverCmd, printenvCmd, "--config", configFile, "--version", "1.0.0+driver"}
			})

			It("should match the saved one", func() {
				Succeed()
				MatchRegexp(driverPrintenvDefaultConfig)
				Expect(string(output.Contents())).To(MatchRegexp(driverPrintenvDefaultConfig))
				// Expect that output is bash setenv compatible
				scanner := bufio.NewScanner(output)
				for scanner.Scan() {
					vals := strings.Split(scanner.Text(), "=")
					Expect(vals).Should(HaveLen(2))
					err := os.Setenv(vals[0], vals[1])
					Expect(err).Should(BeNil())
				}
			})
		})
	})
})
