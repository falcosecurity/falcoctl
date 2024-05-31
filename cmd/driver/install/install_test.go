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

package driverinstall_test

import (
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"

	"github.com/falcosecurity/falcoctl/cmd"
)

//nolint:lll // no need to check for line length.
var driverInstallHelp = `Install previously configured driver, either downloading it or attempting a build.

Usage:
  falcoctl driver install [flags]

Flags:
      --compatible              Whether to enable download of latest compatible driver version instead of the configured one
      --compile                 Whether to enable local compilation of drivers (default true)
      --download                Whether to enable download of prebuilt drivers (default true)
  -h, --help                    help for install
      --http-headers string     Optional comma-separated list of headers for the http GET request (e.g. --http-headers='x-emc-namespace: default,Proxy-Authenticate: Basic'). Not necessary if default repo is used
      --http-insecure           Whether you want to allow insecure downloads or not
      --http-timeout duration   Timeout for each http try (default 1m0s)

Global Flags:
      --config string          config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --host-root string       Driver host root to be used. (default "/")
      --kernelrelease string   Specify the kernel release for which to download/build the driver in the same format used by 'uname -r' (e.g. '6.1.0-10-cloud-amd64')
      --kernelversion string   Specify the kernel version for which to download/build the driver in the same format used by 'uname -v' (e.g. '#1 SMP PREEMPT_DYNAMIC Debian 6.1.38-2 (2023-07-27)')
      --log-format string      Set formatting for logs (color, text, json) (default "color")
      --log-level string       Set level for logs (info, warn, debug, trace) (default "info")
      --name string            Driver name to be used. (default "falco")
      --repo strings           Driver repo to be used. (default [https://download.falco.org/driver])
      --type strings           Driver types allowed in descending priority order (ebpf, kmod, modern_ebpf) (default [modern_ebpf,kmod,ebpf])
      --version string         Driver version to be used.
`

var addAssertFailedBehavior = func(specificError string) {
	It("check that fails and the usage is not printed", func() {
		Expect(err).To(HaveOccurred())
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
	})
}

var addAssertOkBehavior = func(specificOut string) {
	It("check that does not fail and the usage is not printed", func() {
		Succeed()
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificOut)))
	})
}

var _ = Describe("install", func() {

	var (
		driverCmd  = "driver"
		installCmd = "install"
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
			args = []string{driverCmd, installCmd, "--help"}
		})

		It("should match the saved one", func() {
			Expect(output).Should(gbytes.Say(regexp.QuoteMeta(driverInstallHelp)))
		})
	})

	// Here we are testing failure cases for installing a driver.
	Context("failure", func() {
		When("with empty driver version", func() {
			BeforeEach(func() {
				args = []string{driverCmd, installCmd, "--config", configFile}
			})
			addAssertFailedBehavior(`ERROR version is mandatory and cannot be empty`)
		})

		When("with non absolute host-root", func() {
			BeforeEach(func() {
				args = []string{driverCmd, installCmd, "--config", configFile, "--host-root", "foo/", "--version", "1.0.0+driver"}
			})
			addAssertFailedBehavior("ERROR host-root must be an absolute path (foo/)")
		})

		When("with invalid driver type", func() {
			BeforeEach(func() {
				args = []string{driverCmd, installCmd, "--config", configFile, "--type", "foo", "--version", "1.0.0+driver"}
			})
			addAssertFailedBehavior(`ERROR unsupported driver type specified: foo`)
		})
	})

	Context("nothing-to-do", func() {
		When("with false download and compile", func() {
			BeforeEach(func() {
				args = []string{driverCmd, installCmd, "--config", configFile, "--download=false", "--compile=false", "--version", "1.0.0+driver"}
			})
			addAssertOkBehavior("INFO  Nothing to do: download and compile disabled.")
		})
	})
})
