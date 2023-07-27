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
	"os"
	"path/filepath"
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/falcosecurity/falcoctl/cmd"
	"github.com/falcosecurity/falcoctl/internal/utils"
	testutils "github.com/falcosecurity/falcoctl/pkg/test"
)

//nolint:lll,unused // no need to check for line length.
var registryPushUsage = `Usage:
  falcoctl registry push hostname/repo[:tag|@digest] file [flags]

Flags:
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

//nolint:unused // false positive
var pushAssertFailedBehavior = func(usage, specificError string) {
	It("check that fails and the usage is not printed", func() {
		Expect(err).To(HaveOccurred())
		Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(usage)))
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
	})
}

//nolint:unused // false positive
var randomRulesRepoName = func(registry, repo string) (string, string) {
	rName := fmt.Sprintf("%s-%d", repo, rand.Int())
	return rName, fmt.Sprintf("%s/%s", registry, rName)
}

//nolint:unused // false positive
var registryPushTests = Describe("push", func() {
	var (
		registryCmd = "registry"
		pushCmd     = "push"
	)

	const (
		// Used as flags for all the test cases.
		dep1     = "myplugin:1.2.3"
		dep2     = "myplugin1:1.2.3|otherplugin:3.2.1"
		req      = "engine_version:15"
		anSource = "myrepo.com/rules.git"
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
				"invalid reference: invalid digest; invalid checksum digest format\n", newReg))
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

	Context("success", func() {
		const (
			rulesRepoBaseName   = "push-rulesfile"
			pluginsRepoBaseName = "push-plugins"
		)

		var (
			version = "1.1.1"
			// registry/rulesRepoBaseName-randomInt
			fullRepoName string
			// rulesRepoBaseName-randomInt
			repoName string
			// It is set in the config layer.
			artifactNameInConfigLayer = "test-rulesfile"
			pushedTags                = []string{"tag1", "tag2", "latest"}

			// Variables passed as arguments to the push command. Each test case updates them
			// to point to the file on disk living in pkg/test/data.
			rulesfile string
			plugin    string
			pluginRaw string

			// Plugin's platforms.
			platformARM64 = "linux/arm64"
			platformAMD64 = "linux/amd64"

			// Data fetched from registry and used for assertions.
			pluginData    *testutils.PluginArtifact
			rulesfileData *testutils.RulesfileArtifact
		)

		// We keep it inside the success context since need the variables of this context.
		var AssertSuccesBehaviour = func(dependencies, requirements, annotation bool) {
			It("should succeed", func() {
				// We do not check the error here since we are checking it before
				// pulling the artifact.
				By("checking no error in output")
				Expect(output).ShouldNot(gbytes.Say("ERROR"))
				Expect(output).ShouldNot(gbytes.Say("Unable to remove temporary dir"))

				By("checking descriptor")
				Expect(rulesfileData.Descriptor.MediaType).Should(Equal(v1.MediaTypeImageManifest))
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(rulesfileData.Descriptor.Digest.String())))

				By("checking manifest")
				Expect(rulesfileData.Layer.Manifest.Layers).Should(HaveLen(1))
				if annotation {
					Expect(rulesfileData.Layer.Manifest.Annotations).Should(HaveKeyWithValue("org.opencontainers.image.source", anSource))
				} else {
					Expect(rulesfileData.Layer.Manifest.Annotations).ShouldNot(HaveKeyWithValue("org.opencontainers.image.source", anSource))
				}

				By("checking config layer")
				Expect(rulesfileData.Layer.Config.Version).Should(Equal(version))
				Expect(rulesfileData.Layer.Config.Name).Should(Equal(artifactNameInConfigLayer))
				if dependencies {
					Expect(fmt.Sprintf("%s:%s", rulesfileData.Layer.Config.Dependencies[0].Name,
						rulesfileData.Layer.Config.Dependencies[0].Version)).Should(Equal(dep1))
					Expect(fmt.Sprintf("%s:%s|%s:%s", rulesfileData.Layer.Config.Dependencies[1].Name,
						rulesfileData.Layer.Config.Dependencies[1].Version, rulesfileData.Layer.Config.Dependencies[1].Alternatives[0].Name,
						rulesfileData.Layer.Config.Dependencies[1].Alternatives[0].Version)).Should(Equal(dep2))
				} else {
					Expect(rulesfileData.Layer.Config.Dependencies).Should(HaveLen(0))
				}
				if requirements {
					Expect(fmt.Sprintf("%s:%s", rulesfileData.Layer.Config.Requirements[0].Name,
						rulesfileData.Layer.Config.Requirements[0].Version)).Should(Equal(req))
				} else {
					Expect(rulesfileData.Layer.Config.Requirements).Should(HaveLen(0))
				}

				By("checking tags")
				Expect(rulesfileData.Tags).Should(HaveLen(len(pushedTags)))
				Expect(rulesfileData.Tags).Should(ContainElements(pushedTags))
			})
		}

		// Here we are testing all the success cases for the push command. The artifact type used here is of type
		// rulesfile. Keep in mind that here we are testing also the common flags that could be used by the plugin
		// artifacts. So we are testing that common logic only once, and are doing it here.
		commonFlagsAndRulesfileSpecificFlags := Context("rulesfiles and common flags", func() {
			JustBeforeEach(func() {
				// This runs after the push command, so check the returned error before proceeding.
				Expect(err).ShouldNot(HaveOccurred())
				rulesfileData, err = testutils.FetchRulesfileFromRegistry(ctx, repoName, pushedTags[0], orasRegistry)
				Expect(err).ShouldNot(HaveOccurred())
			})

			JustAfterEach(func() {
				// This variable could be changed by single tests.
				// Make sure to set them at their default values.
				artifactNameInConfigLayer = "test-rulesfile"
				pushedTags = []string{"tag1", "tag2", "latest"}
			})

			BeforeEach(func() {
				repoName, fullRepoName = randomRulesRepoName(registry, rulesRepoBaseName)
			})
			When("with full flags and args", func() {
				BeforeEach(func() {
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--requires", req, "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})
				AssertSuccesBehaviour(true, true, true)
			})

			When("no --name flag provided", func() {
				BeforeEach(func() {
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--requires", req, "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2]}
					// Set name to the expected one.
					artifactNameInConfigLayer = repoName
				})
				AssertSuccesBehaviour(true, true, true)
			})

			When("no --annotation-source provided", func() {
				BeforeEach(func() {
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--requires", req,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})
				AssertSuccesBehaviour(true, true, false)
			})

			When("no --tags provided", func() {
				BeforeEach(func() {
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--requires", req, "--annotation-source", anSource,
						"--name", artifactNameInConfigLayer}
					// We expect that latest tag is pushed, so set it in the pushed tags.
					pushedTags = []string{"latest"}
				})
				AssertSuccesBehaviour(true, true, true)
			})

			When("no --depends-on flag provided", func() {
				BeforeEach(func() {
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--requires", req, "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})
				AssertSuccesBehaviour(false, true, true)
			})

			When("no --requires flag provided", func() {
				BeforeEach(func() {
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})
				AssertSuccesBehaviour(true, false, true)
			})

			When("only required flags", func() {
				BeforeEach(func() {
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http"}
					// Set name to the expected one.
					artifactNameInConfigLayer = repoName
					// We expect that latest tag is pushed, so set it in the pushed tags.
					pushedTags = []string{"latest"}
				})
				AssertSuccesBehaviour(false, false, false)
			})
		})

		Context("rulesfile", func() {
			Context("tar.gz format", func() {
				rulesfile = rulesfiletgz
				var _ = commonFlagsAndRulesfileSpecificFlags
			})

			Context("raw format", func() {
				rulesfile = rulesfileyaml

				// Push a raw rulesfiles using all the flags combinations.
				var _ = commonFlagsAndRulesfileSpecificFlags

				Context("filesystem cleanup", func() {
					// Push a raw rulesfile.
					BeforeEach(func() {
						// Some values such as fullRepoName is the last one set by the other tests or the default one.
						// Anyway we do not really care since the tar.gz is created before.
						args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
							"--plain-http"}
					})

					It("temp dir should not exist", func() {
						Expect(err).ShouldNot(HaveOccurred())
						entries, err := os.ReadDir("/tmp")
						Expect(err).ShouldNot(HaveOccurred())
						for _, e := range entries {
							if e.IsDir() {
								matched, err := filepath.Match(utils.TmpDirPrefix+"*", regexp.QuoteMeta(e.Name()))
								Expect(err).ShouldNot(HaveOccurred())
								Expect(matched).ShouldNot(BeTrue())
							}
						}
					})
				})

			})
		})

		// We keep it inside the success context since need the variables of this context.
		var AssertSuccessBehaviourPlugins = func(dependencies, requirements, annotation bool) {
			It("should succeed", func() {
				// We do not check the error here since we are checking it before
				// pulling the artifact.
				By("checking no error in output")
				Expect(output).ShouldNot(gbytes.Say("ERROR"))
				Expect(output).ShouldNot(gbytes.Say("Unable to remove temporary dir"))

				By("checking descriptor")
				Expect(pluginData.Descriptor.MediaType).Should(Equal(v1.MediaTypeImageIndex))
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(pluginData.Descriptor.Digest.String())))

				By("checking index")
				Expect(pluginData.Index.Manifests).Should(HaveLen(2))

				if annotation {
					Expect(pluginData.Index.Annotations).Should(HaveKeyWithValue("org.opencontainers.image.source", anSource))
				} else {
					Expect(pluginData.Descriptor.Annotations).ShouldNot(HaveKeyWithValue("org.opencontainers.image.source", anSource))
				}

				By("checking platforms")
				Expect(pluginData.Platforms).Should(HaveKey(platformARM64))
				Expect(pluginData.Platforms).Should(HaveKey(platformAMD64))

				By("checking config layer")
				for _, p := range pluginData.Platforms {
					Expect(p.Config.Version).Should(Equal(version))
					Expect(p.Config.Name).Should(Equal(artifactNameInConfigLayer))
					if dependencies {
						Expect(fmt.Sprintf("%s:%s", p.Config.Dependencies[0].Name, p.Config.Dependencies[0].Version)).Should(Equal(dep1))
						Expect(fmt.Sprintf("%s:%s|%s:%s", p.Config.Dependencies[1].Name, p.Config.Dependencies[1].Version,
							p.Config.Dependencies[1].Alternatives[0].Name, p.Config.Dependencies[1].Alternatives[0].Version)).Should(Equal(dep2))
					} else {
						Expect(p.Config.Dependencies).Should(HaveLen(0))
					}
					if requirements {
						Expect(fmt.Sprintf("%s:%s", p.Config.Requirements[0].Name, p.Config.Requirements[0].Version)).Should(Equal(req))
					} else {
						Expect(p.Config.Requirements).Should(HaveLen(0))
					}

				}

				By("checking tags")
				Expect(pluginData.Tags).Should(HaveLen(len(pushedTags)))
				Expect(pluginData.Tags).Should(ContainElements(pushedTags))
			})
		}

		// Here we are testing the success cases for the push command using a plugin artifact and its related flags.
		// Other flags related to the plugin artifacts are tested in the rulesfile artifact section.
		PluginsSpecificFlags := Context("plugins specific flags", func() {
			JustBeforeEach(func() {
				// This runs after the push command, so check the returned error before proceeding.
				Expect(err).ShouldNot(HaveOccurred())
				pluginData, err = testutils.FetchPluginFromRegistry(ctx, repoName, pushedTags[0], orasRegistry)
				Expect(err).ShouldNot(HaveOccurred())
			})

			JustAfterEach(func() {
				// This variable could be changed by single tests.
				// Make sure to set them at their default values.
				artifactNameInConfigLayer = "test-plugin"
				pushedTags = []string{"tag1", "tag2", "latest"}
			})

			BeforeEach(func() {
				repoName, fullRepoName = randomRulesRepoName(registry, pluginsRepoBaseName)
			})
			When("with full flags and args", func() {
				BeforeEach(func() {
					args = []string{registryCmd, pushCmd, fullRepoName, plugin, pluginRaw, "--type", "plugin", "--platform",
						platformAMD64, "--platform", platformARM64, "--version", version, "--config", configFile,
						"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--requires", req, "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})
				AssertSuccessBehaviourPlugins(true, true, true)
			})
		})

		Context("plugin", func() {
			Context("tar.gz + raw format format", func() {
				plugin = plugintgz
				// We do not really care what the file is.
				pluginRaw = rulesfileyaml
				var _ = PluginsSpecificFlags
			})
		})
	})
})
