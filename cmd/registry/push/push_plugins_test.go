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
//

package push_test

// revive:disable

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/falcosecurity/falcoctl/cmd"
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	testutils "github.com/falcosecurity/falcoctl/pkg/test"
)

// revive:enable
var _ = Describe("pushing plugins", func() {
	var (
		registryCmd = "registry"
		pushCmd     = "push"
		version     = "1.1.1"
		// fullRepoName is set each time before each test.
		fullRepoName string
		// repoName same as fullRepoName.
		repoName string
		// It is set in the config layer.
		artifactNameInConfigLayer = "test-push-plugins"
		pushedTags                = []string{"tag1", "tag2", "latest"}

		// Plugin's platforms.
		platformARM64 = "linux/arm64"
		platformAMD64 = "linux/amd64"

		// Paths pointing to plugins that will be pushed.
		// Some of the functions expect these two variable to be set to valid paths.
		// They are set in beforeEach blocks by tests that need them.
		pluginOne string
		pluginTwo string
		// Data fetched from registry and used for assertions.
		pluginData *testutils.PluginArtifact
	)

	const (
		// Used as flags for all the test cases.
		requirement         = "plugin_api_version:3.2.1"
		anSource            = "myrepo.com/rules.git"
		pluginsRepoBaseName = "push-plugins-tests"
	)

	var AssertSuccessBehaviour = func(deps []oci.ArtifactDependency, reqs []oci.ArtifactRequirement, annotations map[string]string, platforms []string) {
		It("should succeed", func() {
			// We do not check the error here since we are checking it after
			// pushing the artifact.
			By("checking no error in output")
			Expect(output).ShouldNot(gbytes.Say("ERROR"))
			Expect(output).ShouldNot(gbytes.Say("Unable to remove temporary dir"))

			By("checking descriptor")
			Expect(pluginData.Descriptor.MediaType).Should(Equal(v1.MediaTypeImageIndex))
			Expect(output).Should(gbytes.Say(regexp.QuoteMeta(pluginData.Descriptor.Digest.String())))

			By("checking index")
			Expect(pluginData.Index.Manifests).Should(HaveLen(len(platforms)))

			By("checking platforms")
			for _, p := range platforms {
				Expect(pluginData.Platforms).Should(HaveKey(p))
			}

			By("checking config layers")
			for plat, p := range pluginData.Platforms {
				By(fmt.Sprintf("platform %s", plat))
				Expect(p.Config.Version).Should(Equal(version))
				Expect(p.Config.Name).Should(Equal(artifactNameInConfigLayer))

				By("checking dependencies")
				Expect(p.Config.Dependencies).Should(HaveLen(len(deps)))
				for _, dep := range deps {
					Expect(p.Config.Dependencies).Should(ContainElement(dep))
				}

				By("checking requirements")
				Expect(p.Config.Requirements).Should(HaveLen(len(reqs)))
				for _, req := range reqs {
					Expect(p.Config.Requirements).Should(ContainElement(req))
				}

				By("checking annotations")
				// The creation timestamp is always present.
				Expect(p.Manifest.Annotations).Should(HaveLen(len(annotations) + 1))
				for key, val := range annotations {
					Expect(p.Manifest.Annotations).Should(HaveKeyWithValue(key, val))
				}
			}

			By("checking tags")
			Expect(pluginData.Tags).Should(HaveLen(len(pushedTags)))
			Expect(pluginData.Tags).Should(ContainElements(pushedTags))

			By("checking that temporary dirs have been removed")

			Eventually(func() bool {
				entries, err := os.ReadDir("/tmp")
				Expect(err).ShouldNot(HaveOccurred())
				for _, e := range entries {
					if e.IsDir() {
						matched, err := filepath.Match(utils.TmpDirPrefix+"*", regexp.QuoteMeta(e.Name()))
						Expect(err).ShouldNot(HaveOccurred())
						if matched {
							return true
						}
					}
				}
				return false
			}).WithTimeout(5 * time.Second).Should(BeFalse())
		})
	}

	// Each test gets its own root command and runs it.
	// The err variable is asserted by each test.
	JustBeforeEach(func() {
		rootCmd = cmd.New(ctx, opt)
		err = executeRoot(args)
	})

	JustAfterEach(func() {
		// Reset the status after each test.
		// This variable could be changed by single tests.
		// Make sure to set them at their default values.
		Expect(output.Clear()).ShouldNot(HaveOccurred())
		artifactNameInConfigLayer = "test-plugin"
		pushedTags = []string{"tag1", "tag2", "latest"}
		pluginOne = ""
		pluginTwo = ""
	})

	Context("success", func() {
		JustBeforeEach(func() {
			// Check the returned error before proceeding.
			Expect(err).ShouldNot(HaveOccurred())
			pluginData, err = testutils.FetchPluginFromRegistry(ctx, repoName, pushedTags[0], orasRegistry)
			Expect(err).ShouldNot(HaveOccurred())
		})

		When("two platforms, with reqs and deps", func() {
			BeforeEach(func() {
				repoName, fullRepoName = randomRulesRepoName(registry, pluginsRepoBaseName)
				pluginOne = rulesfileyaml
				pluginTwo = plugintgz

				args = []string{registryCmd, pushCmd, fullRepoName, pluginOne, pluginTwo, "--type", "plugin", "--platform",
					platformAMD64, "--platform", platformARM64, "--version", version, "--config", configFile,
					"--plain-http", "--depends-on", "my-test:4.3.2", "--requires", requirement, "--annotation-source", anSource,
					"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
			})

			AssertSuccessBehaviour([]oci.ArtifactDependency{{
				Name:         "my-test",
				Version:      "4.3.2",
				Alternatives: nil,
			}}, []oci.ArtifactRequirement{
				{
					Name:    "plugin_api_version",
					Version: "3.2.1",
				},
			}, map[string]string{
				"org.opencontainers.image.source": anSource,
			}, []string{
				platformAMD64, platformARM64,
			})
		})

		When("one platform, no reqs", func() {
			BeforeEach(func() {
				repoName, fullRepoName = randomRulesRepoName(registry, pluginsRepoBaseName)
				pluginOne = plugintgz
				args = []string{registryCmd, pushCmd, fullRepoName, pluginOne, "--type", "plugin", "--platform",
					platformAMD64, "--version", version, "--config", configFile,
					"--plain-http", "--depends-on", "my-test:4.3.2", "--annotation-source", anSource,
					"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
			})
			// We expect to succeed and that the requirement is empty.
			AssertSuccessBehaviour([]oci.ArtifactDependency{{
				Name:         "my-test",
				Version:      "4.3.2",
				Alternatives: nil,
			}}, []oci.ArtifactRequirement{}, map[string]string{
				"org.opencontainers.image.source": anSource,
			}, []string{
				platformAMD64,
			})
		})
	})
})
