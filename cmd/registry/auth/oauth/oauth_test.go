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

package oauth_test

import (
	"fmt"
	"os"
	"regexp"

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

//nolint:unused // false positive
var correctIndexConfig = `indexes:
- name: falcosecurity
  url: https://falcosecurity.github.io/falcoctl/index.yaml
`

//nolint:lll,unused // no need to check for line length.
var registryAuthOAuthUsage = `Usage:
  falcoctl registry auth oauth [HOSTNAME]

Flags:
      --client-id string       client ID of the OAuth2.0 app
      --client-secret string   client secret of the OAuth2.0 app
  -h, --help                   help for oauth
      --scopes strings         comma separeted list of scopes for which requesting access
      --token-url string       token URL used to get access and refresh tokens

Global Flags:
      --config string     config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --disable-styling   Disable output styling such as spinners, progress bars and colors. Styling is automatically disabled if not attacched to a tty (default false)
  -v, --verbose           Enable verbose logs (default false)
`

//nolint:unused // false positive
var registryAuthOAuthHelp = `Store client credentials for later OAuth2.0 authentication

Client credentials will be saved in the ~/.config directory.

Example
	falcoctl registry oauth \
		--token-url="http://localhost:9096/token" \
		--client-id=000000 \
		--client-secret=999999  --scopes="my-scope" \
		hostname
`

//nolint:unused // false positive
var registryAuthOAuthAssertFailedBehavior = func(usage, specificError string) {
	It("check that fails and the usage is not printed", func() {
		Expect(err).To(HaveOccurred())
		Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(usage)))
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
	})
}

//nolint:unused // false positive
var registryAuthOAuthTests = Describe("auth", func() {
	const (
		// Used as flags for all the test cases.
		registryCmd = "registry"
		authCmd     = "auth"
		oauthCmd    = "oauth"
		anSource    = "myrepo.com/rules.git"
		artifact    = "generic-repo"
		repo        = "/" + artifact
		tag         = "tag"
		repoAndTag  = repo + ":" + tag
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
			args = []string{registryCmd, authCmd, oauthCmd, "--help"}
		})

		It("should match the saved one", func() {
			Expect(output).Should(gbytes.Say(regexp.QuoteMeta(registryAuthOAuthHelp)))
		})
	})
	Context("failure", func() {

		When("without hostname", func() {
			BeforeEach(func() {
				args = []string{registryCmd, authCmd, oauthCmd}
			})
			registryAuthOAuthAssertFailedBehavior(registryAuthOAuthUsage,
				"ERRO: accepts 1 arg(s), received 0")
		})

		When("wrong client id", func() {
			BeforeEach(func() {

				baseDir := GinkgoT().TempDir()
				configFilePath := baseDir + "/config.yaml"
				content := []byte(correctIndexConfig)
				err = os.WriteFile(configFilePath, content, 0o644)
				Expect(err).To(BeNil())

				args = []string{registryCmd, authCmd, oauthCmd,
					"--client-id=000001", "--client-secret=999999",
					"--token-url", fmt.Sprintf("http://localhost:%d/token", oauthPort),
					"--config", configFilePath,
					"127.0.0.1:5000",
				}
			})
			registryAuthOAuthAssertFailedBehavior(registryAuthOAuthUsage,
				`ERRO: wrong client credentials, unable to retrieve token`)
		})

		When("wrong client secret", func() {
			BeforeEach(func() {
				// start the OAuthServer
				baseDir := GinkgoT().TempDir()
				configFilePath := baseDir + "/config.yaml"
				content := []byte(correctIndexConfig)
				err := os.WriteFile(configFilePath, content, 0o644)
				Expect(err).To(BeNil())

				args = []string{registryCmd, authCmd, oauthCmd,
					"--client-id=000000", "--client-secret=999998",
					"--token-url", fmt.Sprintf("http://localhost:%d/token", oauthPort),
					"--config", configFilePath,
					"127.0.0.1:5000",
				}
			})
			registryAuthOAuthAssertFailedBehavior(registryAuthOAuthUsage,
				`ERRO: wrong client credentials, unable to retrieve token`)
		})
	})

	Context("success", func() {
		var (
			configFilePath string
		)

		When("all good", func() {
			BeforeEach(func() {
				baseDir := GinkgoT().TempDir()
				configFilePath = baseDir + "/config.yaml"
				content := []byte(correctIndexConfig)
				err = os.WriteFile(configFilePath, content, 0o644)
				Expect(err).To(BeNil())

				args = []string{registryCmd, authCmd, oauthCmd,
					"--client-id=000000", "--client-secret=999999",
					"--token-url", fmt.Sprintf("http://localhost:%d/token", oauthPort),
					"--config", configFilePath,
					registry,
				}
			})

			It("should successed", func() {
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(
					`INFO: client credentials correctly saved in`)))
			})
		})

	})
})
