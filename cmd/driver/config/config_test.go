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

package driverconfig_test

import (
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"

	"github.com/falcosecurity/falcoctl/cmd"
)

var driverConfigHelp = `Configure a driver for future usages with other driver subcommands.`

var addAssertFailedBehavior = func(specificError string) {
	It("check that fails and the usage is not printed", func() {
		Expect(err).To(HaveOccurred())
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
	})
}

var _ = Describe("config", func() {

	var (
		driverCmd = "driver"
		configCmd = "config"
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
			args = []string{driverCmd, configCmd, "--help"}
		})

		It("should match the saved one", func() {
			Expect(output).Should(gbytes.Say(driverConfigHelp))
		})
	})

	// Here we are testing failure cases for configuring a driver.
	Context("failure", func() {
		When("with non absolute host-root", func() {
			BeforeEach(func() {
				args = []string{driverCmd, configCmd, "--config", configFile, "--host-root", "foo/"}
			})
			addAssertFailedBehavior("ERROR host-root must be an absolute path: foo/")
		})

		When("with invalid driver type", func() {
			BeforeEach(func() {
				args = []string{driverCmd, configCmd, "--config", configFile, "--type", "foo"}
			})
			addAssertFailedBehavior(`ERROR invalid argument "foo" for "--type" flag: invalid argument "foo",` +
				` please provide one of (auto, ebpf, kmod, modern_ebpf)`)
		})
	})
})
