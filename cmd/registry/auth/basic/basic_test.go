// Copyright 2023 The Falco Authors
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
var registryAuthBasicHelp = `Login to an OCI registry to push and pull artifacts`

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
	Context("failure", func() {

		When("without hostname", func() {
			BeforeEach(func() {
				args = []string{registryCmd, authCmd, basicCmd}
			})
			registryAuthBasicAssertFailedBehavior(registryAuthBasicUsage,
				"ERRO: accepts 1 arg(s), received 0")
		})

		/*
					When("wrong credentials", func() {
						BeforeEach(func() {

							ptyFile, ttyFile, err := pty.Open()
							Expect(err).To(BeNil())

							os.Stdin = ttyFile
							input := `username1
			password1
			`
							_, err = ptyFile.Write([]byte(input))
							Expect(err).To(BeNil())

							http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

							args = []string{registryCmd, authCmd, basicCmd, "--config", configFile, registryBasic}
						})

						registryAuthBasicAssertFailedBehavior(registryAuthBasicUsage,
							"ERRO: accepts 0 arg(s), received 0")
					})
		*/
	})

})
