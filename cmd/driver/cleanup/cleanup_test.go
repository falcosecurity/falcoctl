// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package drivercleanup_test

import (
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"

	"github.com/falcosecurity/falcoctl/cmd"
)

//nolint:lll // no need to check for line length.
var driverCleanupHelp = `[Preview] Cleans a driver up, eg for kmod, by removing it from dkms.
** This command is in preview and under development. **

Usage:
  falcoctl driver cleanup [flags]

Flags:
  -h, --help   help for cleanup

Global Flags:
      --config string          config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --host-root string       Driver host root to be used. (default "/")
      --kernelrelease string   Specify the kernel release for which to download/build the driver in the same format used by 'uname -r' (e.g. '6.1.0-10-cloud-amd64')
      --kernelversion string   Specify the kernel version for which to download/build the driver in the same format used by 'uname -v' (e.g. '#1 SMP PREEMPT_DYNAMIC Debian 6.1.38-2 (2023-07-27)')
      --log-format string      Set formatting for logs (color, text, json) (default "color")
      --log-level string       Set level for logs (info, warn, debug, trace) (default "info")
      --name string            Driver name to be used. (default "falco")
      --repo strings           Driver repo to be used. (default [https://download.falco.org/driver])
      --type strings           Driver types allowed in descending priority order (ebpf, kmod, modern_ebpf) (default [modern_ebpf,ebpf,kmod])
      --version string         Driver version to be used.
`

var addAssertFailedBehavior = func(specificError string) {
	It("check that fails and the usage is not printed", func() {
		Expect(err).To(HaveOccurred())
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
	})
}

var _ = Describe("cleanup", func() {

	var (
		driverCmd  = "driver"
		cleanupCmd = "cleanup"
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
			args = []string{driverCmd, cleanupCmd, "--help"}
		})

		It("should match the saved one", func() {
			Expect(output).Should(gbytes.Say(regexp.QuoteMeta(driverCleanupHelp)))
		})
	})

	// Here we are testing failure cases for cleaning a driver.
	Context("failure", func() {
		When("with non absolute host-root", func() {
			BeforeEach(func() {
				args = []string{driverCmd, cleanupCmd, "--config", configFile, "--host-root", "foo/"}
			})
			addAssertFailedBehavior("ERROR host-root must be an absolute path (foo/)")
		})

		When("with invalid driver type", func() {
			BeforeEach(func() {
				args = []string{driverCmd, cleanupCmd, "--config", configFile, "--type", "foo"}
			})
			addAssertFailedBehavior(`ERROR unsupported driver type specified: foo`)
		})
	})
})
