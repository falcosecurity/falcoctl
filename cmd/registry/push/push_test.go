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

package push_test

import (
	"fmt"
	"math/rand"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"

	"github.com/falcosecurity/falcoctl/cmd"
)

var registryPushUsage = `Usage:
  falcoctl registry push hostname/repo[:tag|@digest] file [flags]

Flags:
      --add-floating-tags          add the floating tags for the major and minor versions
      --annotation-source string   set annotation source for the artifact
  -d, --depends-on stringArray     set an artifact dependency (can be specified multiple times). Example: "--depends-on my-plugin:1.2.3"
  -h, --help                       help for push
      --name string                set the unique name of the artifact (if not set, the name is extracted from the reference)
      --plain-http                 allows interacting with remote registry via plain http requests
      --platform stringArray       os and architecture of the artifact in OS/ARCH format (only for plugins artifacts)
  -r, --requires stringArray       set an artifact requirement (can be specified multiple times). Example: "--requires plugin_api_version:1.2.3"
  -t, --tag stringArray            additional artifact tag. Can be repeated multiple times
      --type ArtifactType          type of artifact to be pushed. Allowed values: "rulesfile", "plugin", "asset" (default )
      --version string             set the version of the artifact

Global Flags:
      --config string       config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --log-format string   Set formatting for logs (color, text, json) (default "color")
      --log-level string    Set level for logs (info, warn, debug, trace) (default "info")
`

//nolint:lll,unused // no need to check for line length.
var registryPushHelp = `Push Falco "rulesfile" or "plugin" OCI artifacts to remote registry

Example - Push artifact "myplugin.tar.gz" of type "plugin" for the platform where falcoctl is running (default):
	falcoctl registry push --type plugin --version "1.2.3" localhost:5000/myplugin:latest myplugin.tar.gz

Example - Push artifact "myplugin.tar.gz" of type "plugin" for platform "linux/arm64":
	falcoctl registry push --type plugin --version "1.2.3" localhost:5000/myplugin:latest myplugin.tar.gz --platform linux/arm64

Example - Push artifact "myplugin.tar.gz" of type "plugin" for multiple platforms:
	falcoctl registry push --type plugin --version "1.2.3" localhost:5000/myplugin:latest \
		myplugin-linux-x86_64.tar.gz --platform linux/x86_64 \
		myplugin-linux-arm64.tar.gz --platform linux/arm64

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile":
	falcoctl registry push --type rulesfile --version "0.1.2" localhost:5000/myrulesfile:latest myrulesfile.tar.gz

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with floating tags for the major and minor versions (0 and 0.1):
	falcoctl registry push --type rulesfile --version "0.1.2" localhost:5000/myrulesfile:latest myrulesfile.tar.gz \
	        --add-floating-tags

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" to an insecure registry:
	falcoctl registry push --type rulesfile --version "0.1.2" --plain-http localhost:5000/myrulesfile:latest myrulesfile.tar.gz

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with a dependency "myplugin:1.2.3":
	falcoctl registry push --type rulesfile --version "0.1.2" localhost:5000/myrulesfile:latest myrulesfile.tar.gz \
	        --depends-on myplugin:1.2.3

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with a dependency "myplugin:1.2.3" and an alternative "otherplugin:3.2.1":
	falcoctl registry push --type rulesfile --version "0.1.2" localhost:5000/myrulesfile:latest myrulesfile.tar.gz \
	        --depends-on "myplugin:1.2.3|otherplugin:3.2.1"

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with multiple dependencies "myplugin:1.2.3", "otherplugin:3.2.1":
        falcoctl registry push --type rulesfile --version "0.1.2" localhost:5000/myrulesfile:latest myrulesfile.tar.gz \
		--depends-on myplugin:1.2.3 \
		--depends-on otherplugin:3.2.1

Usage:
  falcoctl registry push hostname/repo[:tag|@digest] file [flags]

Flags:
      --add-floating-tags          add the floating tags for the major and minor versions
      --annotation-source string   set annotation source for the artifact
  -d, --depends-on stringArray     set an artifact dependency (can be specified multiple times). Example: "--depends-on my-plugin:1.2.3"
  -h, --help                       help for push
      --name string                set the unique name of the artifact (if not set, the name is extracted from the reference)
      --plain-http                 allows interacting with remote registry via plain http requests
      --platform stringArray       os and architecture of the artifact in OS/ARCH format (only for plugins artifacts)
  -r, --requires stringArray       set an artifact requirement (can be specified multiple times). Example: "--requires plugin_api_version:1.2.3"
  -t, --tag stringArray            additional artifact tag. Can be repeated multiple times
      --type ArtifactType          type of artifact to be pushed. Allowed values: "rulesfile", "plugin", "asset"
      --version string             set the version of the artifact

Global Flags:
      --config string       config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --log-format string   Set formatting for logs (color, text, json) (default "color")
      --log-level string    Set level for logs (info, warn, debug, trace) (default "info")
`

var pushAssertFailedBehavior = func(usage, specificError string) {
	It("check that fails and the usage is not printed", func() {
		Expect(err).To(HaveOccurred())
		Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(usage)))
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
	})
}

var randomRulesRepoName = func(registry, repo string) (string, string) {
	rName := fmt.Sprintf("%s-%d", repo, rand.Int())
	return rName, fmt.Sprintf("%s/%s", registry, rName)
}

var _ = Describe("push", func() {
	var (
		registryCmd = "registry"
		pushCmd     = "push"
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
			args = []string{registryCmd, pushCmd, "--help"}
		})

		It("should match the saved one", func() {
			outputMsg := string(output.Contents())
			Expect(outputMsg).Should(Equal(registryPushHelp))
		})
	})

	// Here we are testing all the failure cases using both the rulesfile and plugin artifact types.
	// The common logic for the artifacts is tested once using a rulesfile artifact, no need to repeat
	// the same test using a plugin artifact.
	Context("failure", func() {
		var (
			// Not really used since all the tests fail but needed as argument.
			rulesRepo   = registry + "/push-rulesfile"
			pluginsRepo = registry + "/push-plugin"
		)
		When("without --version flag", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, "--config", configFile, rulesRepo, rulesfiletgz, "--type", "rulesfile"}
			})
			pushAssertFailedBehavior(registryPushUsage, "ERROR required flag(s) \"version\" not set")
		})

		When("without rulesfile", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, "--config", configFile, rulesRepo, "--type", "rulesfile"}
			})
			pushAssertFailedBehavior(registryPushUsage, "ERROR requires at least 2 arg(s), only received 1")
		})

		When("without registry", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, "--config", configFile, rulesfiletgz, "--type", "rulesfile"}
			})
			pushAssertFailedBehavior(registryPushUsage, "ERROR requires at least 2 arg(s), only received 1")
		})

		When("multiple rulesfiles", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, "--config", configFile,
					"--type", "rulesfile", "--version", "1.1.1", "--plain-http", rulesRepo, rulesfiletgz, rulesfiletgz}
			})
			pushAssertFailedBehavior(registryPushUsage, "ERROR expecting 1 rulesfile object, received 2: invalid number of rulesfiles")
		})

		When("unreachable registry", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, "noregistry/testrules", "--config", configFile, rulesfiletgz,
					"--type", "rulesfile", "--version", "1.1.1", "--plain-http"}
			})
			pushAssertFailedBehavior(registryPushUsage, "ERROR unable to connect to remote "+
				"registry \"noregistry\": Get \"http://noregistry/v2/\": dial tcp: lookup noregistry")
		})

		When("wrong semver for --version flag with --add-floating-tags", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, rulesRepo, rulesfiletgz, "--config", configFile, "--type", "rulesfile",
					"--version", "notSemVer", "--add-floating-tags", "--plain-http"}
			})
			pushAssertFailedBehavior(registryPushUsage, "ERROR expected semver for the flag \"--version\": No Major.Minor.Patch elements found")
		})

		When("invalid character in semver for --version flag with --add-floating-tags", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, rulesRepo, rulesfiletgz, "--config", configFile, "--type", "rulesfile",
					"--version", "1.1.a", "--add-floating-tags", "--plain-http"}
			})
			pushAssertFailedBehavior(registryPushUsage, "ERROR expected semver for the flag \"--version\": Invalid character(s) found in patch number \"a\"")
		})

		When("missing repository", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, registry, rulesfiletgz, "--config", configFile, "--type", "rulesfile", "--version", "1.1.1", "--plain-http"}
			})
			pushAssertFailedBehavior(registryPushUsage, fmt.Sprintf("ERROR cannot extract registry name from ref %q", registry))
		})

		When("invalid repository", func() {
			newReg := registry + "/wrong@something"
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, newReg, rulesfiletgz, "--config", configFile, "--type", "rulesfile", "--version", "1.1.1", "--plain-http"}
			})
			pushAssertFailedBehavior(registryPushUsage, fmt.Sprintf("ERROR unable to create new repository with ref %s: "+
				"invalid reference: invalid digest %q: invalid checksum digest format\n", newReg, "something"))
		})

		When("invalid requirement", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, rulesRepo, rulesfiletgz, "--config", configFile, "--type", "rulesfile", "--version", "1.1.1",
					"--plain-http", "--requires", "wrongreq"}
			})
			pushAssertFailedBehavior(registryPushUsage, "ERROR cannot parse \"wrongreq\"")
		})

		When("invalid dependency", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, rulesRepo, rulesfiletgz, "--config", configFile, "--type", "rulesfile",
					"--version", "1.1.1", "--plain-http", "--depends-on", "wrongdep"}
			})
			pushAssertFailedBehavior(registryPushUsage, "ERROR cannot parse \"wrongdep\": invalid artifact reference "+
				"(must be in the format \"name:version\")\n")
		})

		When("without platform", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, pluginsRepo, plugintgz, "--config", configFile, "--type", "plugin", "--version", "1.1.1", "--plain-http"}
			})
			pushAssertFailedBehavior(registryPushUsage, "ERROR \"filepaths\" length (1) must match \"platforms\" "+
				"length (0): number of filepaths and platform should be the same")
		})

		When("wrong plugin type", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pushCmd, pluginsRepo, pluginsRepo, "--config", configFile,
					"--type", "wrongType", "--version", "1.1.1", "--plain-http"}
			})
			pushAssertFailedBehavior(registryPushUsage, "ERROR invalid argument \"wrongType\" for \"--type\" "+
				"flag: must be one of \"rulesfile\", \"plugin\", \"asset")
		})
	})
})
