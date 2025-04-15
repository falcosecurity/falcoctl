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

package basic_test

import (
	"regexp"

	_ "github.com/distribution/distribution/v3/registry/auth/htpasswd"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"

	"github.com/falcosecurity/falcoctl/cmd"
)

type Config struct {
	Registry Registry `yaml:"registry"`
}

type Registry struct {
	Auth Auth `yaml:"auth"`
}

type Auth struct {
	OAuth []OAuth `yaml:"oauth"`
}

type OAuth struct {
	Registry     string `yaml:"registry"`
	ClientSecret string `yaml:"clientsecret"`
	ClientID     string `yaml:"clientid"`
	TokerURL     string `yaml:"tokenurl"`
}

//nolint:lll,unused // no need to check for line length.
var registryAuthBasicUsage = `Usage:
  falcoctl registry auth basic [hostname]

Flags:
  -h, --help   help for basic

Global Flags:
      --config string     config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --disable-styling   Disable output styling such as spinners, progress bars and colors. Styling is automatically disabled if not attacched to a tty (default false)
  -v, --verbose           Enable verbose logs (default false)
`

//nolint:unused // false positive
var registryAuthBasicHelp = `Login to an OCI registry

Example - Log in with username and password from command line flags:
	falcoctl registry auth basic -u username -p password localhost:5000

Example - Login with username and password from env variables:
	FALCOCTL_REGISTRY_AUTH_BASIC_USERNAME=username FALCOCTL_REGISTRY_AUTH_BASIC_PASSWORD=password falcoctl registry auth basic localhost:5000

Example - Login with username and password from stdin:
	falcoctl registry auth basic -u username --password-stdin localhost:5000

Example - Login with username and password in an interactive prompt:
	falcoctl registry auth basic localhost:5000

Example - Login to an insecure registry:
	falcoctl registry auth basic --insecure localhost:5000

Usage:
  falcoctl registry auth basic [hostname]

Flags:
  -h, --help              help for basic
      --insecure          allow connections to SSL registry without certs
  -p, --password string   registry password
      --password-stdin    read password from stdin
  -u, --username string   registry username

Global Flags:
      --config string       config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --log-format string   Set formatting for logs (color, text, json) (default "color")
      --log-level string    Set level for logs (info, warn, debug, trace) (default "info")
`

//nolint:unused // false positive
var registryAuthBasicAssertFailedBehavior = func(usage, specificError string) {
	It("check that fails and the usage is not printed", func() {
		Expect(err).To(HaveOccurred())
		Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(usage)))
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
	})
}

//nolint:unused // false positive
var registryAuthBasicTests = Describe("auth", func() {

	const (
		// Used as flags for all the test cases.
		registryCmd = "registry"
		authCmd     = "auth"
		basicCmd    = "basic"
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
			args = []string{registryCmd, authCmd, basicCmd, "--help"}
		})

		It("should match the saved one", func() {
			Expect(output).Should(gbytes.Say(regexp.QuoteMeta(registryAuthBasicHelp)))
		})
	})

	Context("insecure flag", func() {
		When("using HTTP with --insecure", func() {
			BeforeEach(func() {
				args = []string{registryCmd, authCmd, basicCmd, "--insecure", "-u", "username", "-p", "password", "--config", configFile, registry}
			})

			It("should succeed with plain HTTP", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(output).Should(gbytes.Say("Login succeeded"))
			})
		})

		When("using HTTPS with self-signed cert and --insecure", func() {
			BeforeEach(func() {
				// The registry is already configured for HTTPS in the test suite
				args = []string{registryCmd, authCmd, basicCmd, "--insecure", "-u", "username", "-p", "password", "--config", configFile, registryBasic}
			})

			It("should succeed with insecure HTTPS", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(output).Should(gbytes.Say("Login succeeded"))
			})
		})

		When("using HTTPS without --insecure", func() {
			BeforeEach(func() {
				args = []string{registryCmd, authCmd, basicCmd, "-u", "username", "-p", "password", "--config", configFile, registryBasic}
			})

			It("should fail with certificate verification error", func() {
				Expect(err).Should(HaveOccurred())
				Expect(output).Should(gbytes.Say("certificate"))
			})
		})

		When("using HTTP without --insecure", func() {
			BeforeEach(func() {
				args = []string{registryCmd, authCmd, basicCmd, "-u", "username", "-p", "password", "--config", configFile, "http://" + registry}
			})

			It("should fail when trying plain HTTP without insecure flag", func() {
				Expect(err).Should(HaveOccurred())
			})
		})
	})

	Context("failure", func() {
		When("without hostname", func() {
			BeforeEach(func() {
				args = []string{registryCmd, authCmd, basicCmd}
			})
			registryAuthBasicAssertFailedBehavior(registryAuthBasicUsage,
				"ERROR accepts 1 arg(s), received 0")
		})
	})
})
