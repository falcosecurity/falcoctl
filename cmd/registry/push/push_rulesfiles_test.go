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

var _ = Describe("pushing rulesfiles", func() {
	var (
		registryCmd = "registry"
		pushCmd     = "push"
		version     = "1.1.1"
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

		// Data fetched from registry and used for assertions.
		rulesfileData *testutils.RulesfileArtifact
	)

	const (
		// Used as flags for all the test cases.
		dep1              = "myplugin:1.2.3"
		dep2              = "myplugin1:1.2.3|otherplugin:3.2.1"
		req               = "engine_version_semver:0.37.0"
		anSource          = "myrepo.com/rules.git"
		rulesRepoBaseName = "push-rulesfile"
	)

	// We keep it inside the success context since need the variables of this context.
	var AssertSuccesBehaviour = func(deps []oci.ArtifactDependency, reqs []oci.ArtifactRequirement, annotations map[string]string) {
		It("should succeed", func() {
			// We do not check the error here since we are checking it after
			// pushing the artifact.
			By("checking no error in output")
			Expect(output).ShouldNot(gbytes.Say("ERROR"))
			Expect(output).ShouldNot(gbytes.Say("Unable to remove temporary dir"))

			By("checking descriptor")
			Expect(rulesfileData.Descriptor.MediaType).Should(Equal(v1.MediaTypeImageManifest))
			Expect(output).Should(gbytes.Say(regexp.QuoteMeta(rulesfileData.Descriptor.Digest.String())))

			By("checking manifest")
			Expect(rulesfileData.Layer.Manifest.Layers).Should(HaveLen(1))

			By("checking platforms")
			Expect(rulesfileData.Descriptor.Platform).Should(BeNil())

			By("checking config layer")
			Expect(rulesfileData.Layer.Config.Version).Should(Equal(version))
			Expect(rulesfileData.Layer.Config.Name).Should(Equal(artifactNameInConfigLayer))

			By("checking dependencies")
			Expect(rulesfileData.Layer.Config.Dependencies).Should(HaveLen(len(deps)))
			for _, dep := range deps {
				Expect(rulesfileData.Layer.Config.Dependencies).Should(ContainElement(dep))
			}

			By("checking requirements")
			Expect(rulesfileData.Layer.Config.Requirements).Should(HaveLen(len(reqs)))
			for _, req := range reqs {
				Expect(rulesfileData.Layer.Config.Requirements).Should(ContainElement(req))
			}

			By("checking annotations")
			// The creation timestamp is always present.
			Expect(rulesfileData.Layer.Manifest.Annotations).Should(HaveLen(len(annotations) + 1))
			for key, val := range annotations {
				Expect(rulesfileData.Layer.Manifest.Annotations).Should(HaveKeyWithValue(key, val))
			}

			By("checking tags")
			Expect(rulesfileData.Tags).Should(HaveLen(len(pushedTags)))
			Expect(rulesfileData.Tags).Should(ContainElements(pushedTags))

			By("checking that temporary dirs have been removed")
			Eventually(func() bool {
				entries, err := os.ReadDir("/tmp")
				Expect(err).ShouldNot(HaveOccurred())
				for _, e := range entries {
					if e.IsDir() {
						matched, err := filepath.Match(utils.TmpDirPrefix+"*", regexp.QuoteMeta(e.Name()))
						Expect(err).ShouldNot(HaveOccurred())
						if matched {
							fmt.Println(e.Name())
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
		Expect(output.Clear()).ShouldNot(HaveOccurred())
		// This variable could be changed by single tests.
		// Make sure to set them at their default values.
		artifactNameInConfigLayer = "test-rulesfile"
		pushedTags = []string{"tag1", "tag2", "latest"}
		rulesfile = ""
	})

	Context("success", func() {
		// Here we are testing all the success cases for the push command. The artifact type used here is of type
		// rulesfile. Keep in mind that here we are testing also the common flags that could be used by the plugin
		// artifacts. So we are testing that common logic only once, and are doing it here.

		JustBeforeEach(func() {
			// This runs after the push command, so check the returned error before proceeding.
			Expect(err).ShouldNot(HaveOccurred())
			rulesfileData, err = testutils.FetchRulesfileFromRegistry(ctx, repoName, pushedTags[0], orasRegistry)
			Expect(err).ShouldNot(HaveOccurred())
		})

		BeforeEach(func() {
			repoName, fullRepoName = randomRulesRepoName(registry, rulesRepoBaseName)
		})

		When("with full flags and args", func() {
			BeforeEach(func() {
				rulesfile = rulesfileyaml
				args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
					"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--requires", req, "--annotation-source", anSource,
					"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
			})
			AssertSuccesBehaviour([]oci.ArtifactDependency{
				{
					Name:         "myplugin",
					Version:      "1.2.3",
					Alternatives: nil,
				}, {
					Name:    "myplugin1",
					Version: "1.2.3",
					Alternatives: []oci.Dependency{{
						Name:    "otherplugin",
						Version: "3.2.1",
					},
					},
				},
			}, []oci.ArtifactRequirement{
				{
					Name:    "engine_version_semver",
					Version: "0.37.0",
				},
			}, map[string]string{
				"org.opencontainers.image.source": anSource,
			})
		})

		When("no --name flag provided", func() {
			BeforeEach(func() {
				rulesfile = rulesfileyaml
				args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
					"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--requires", req, "--annotation-source", anSource,
					"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2]}
				// Set name to the expected one.
				artifactNameInConfigLayer = repoName
			})

			AssertSuccesBehaviour([]oci.ArtifactDependency{
				{
					Name:         "myplugin",
					Version:      "1.2.3",
					Alternatives: nil,
				}, {
					Name:    "myplugin1",
					Version: "1.2.3",
					Alternatives: []oci.Dependency{{
						Name:    "otherplugin",
						Version: "3.2.1",
					},
					},
				},
			}, []oci.ArtifactRequirement{
				{
					Name:    "engine_version_semver",
					Version: "0.37.0",
				},
			}, map[string]string{
				"org.opencontainers.image.source": anSource,
			})
		})

		When("no --annotation-source provided", func() {
			BeforeEach(func() {
				rulesfile = rulesfileyaml
				args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
					"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--requires", req,
					"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
			})
			AssertSuccesBehaviour([]oci.ArtifactDependency{
				{
					Name:         "myplugin",
					Version:      "1.2.3",
					Alternatives: nil,
				}, {
					Name:    "myplugin1",
					Version: "1.2.3",
					Alternatives: []oci.Dependency{{
						Name:    "otherplugin",
						Version: "3.2.1",
					},
					},
				},
			}, []oci.ArtifactRequirement{
				{
					Name:    "engine_version_semver",
					Version: "0.37.0",
				},
			}, map[string]string{})
		})

		When("no --tags provided", func() {
			BeforeEach(func() {
				rulesfile = rulesfileyaml
				args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
					"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--requires", req, "--annotation-source", anSource,
					"--name", artifactNameInConfigLayer}
				// We expect that latest tag is pushed, so set it in the pushed tags.
				pushedTags = []string{"latest"}
			})
			AssertSuccesBehaviour([]oci.ArtifactDependency{
				{
					Name:         "myplugin",
					Version:      "1.2.3",
					Alternatives: nil,
				}, {
					Name:    "myplugin1",
					Version: "1.2.3",
					Alternatives: []oci.Dependency{{
						Name:    "otherplugin",
						Version: "3.2.1",
					},
					},
				},
			}, []oci.ArtifactRequirement{
				{
					Name:    "engine_version_semver",
					Version: "0.37.0",
				},
			}, map[string]string{
				"org.opencontainers.image.source": anSource,
			})
		})

		When("no --depends-on flag provided", func() {
			BeforeEach(func() {
				rulesfile = rulesfileyaml
				args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
					"--plain-http", "--requires", req, "--annotation-source", anSource,
					"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
			})
			AssertSuccesBehaviour([]oci.ArtifactDependency{},
				[]oci.ArtifactRequirement{
					{
						Name:    "engine_version_semver",
						Version: "0.37.0",
					},
				}, map[string]string{
					"org.opencontainers.image.source": anSource,
				})
		})

		When("no --requires flag provided", func() {
			BeforeEach(func() {
				rulesfile = rulesfileyaml
				args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
					"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--annotation-source", anSource,
					"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
			})
			AssertSuccesBehaviour([]oci.ArtifactDependency{
				{
					Name:         "myplugin",
					Version:      "1.2.3",
					Alternatives: nil,
				}, {
					Name:    "myplugin1",
					Version: "1.2.3",
					Alternatives: []oci.Dependency{{
						Name:    "otherplugin",
						Version: "3.2.1",
					},
					},
				},
			}, []oci.ArtifactRequirement{}, map[string]string{
				"org.opencontainers.image.source": anSource,
			})
		})

		When("only required flags", func() {
			BeforeEach(func() {
				rulesfile = rulesfileyaml
				args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
					"--plain-http"}
				// Set name to the expected one.
				artifactNameInConfigLayer = repoName
				// We expect that latest tag is pushed, so set it in the pushed tags.
				pushedTags = []string{"latest"}
			})
			AssertSuccesBehaviour([]oci.ArtifactDependency{},
				[]oci.ArtifactRequirement{},
				map[string]string{})
		})

		When("with full flags and args but in tar.gz format", func() {
			BeforeEach(func() {
				rulesfile = rulesfiletgz
				args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
					"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--requires", req, "--annotation-source", anSource,
					"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
			})
			AssertSuccesBehaviour([]oci.ArtifactDependency{
				{
					Name:         "myplugin",
					Version:      "1.2.3",
					Alternatives: nil,
				}, {
					Name:    "myplugin1",
					Version: "1.2.3",
					Alternatives: []oci.Dependency{{
						Name:    "otherplugin",
						Version: "3.2.1",
					},
					},
				},
			}, []oci.ArtifactRequirement{
				{
					Name:    "engine_version_semver",
					Version: "0.37.0",
				},
			}, map[string]string{
				"org.opencontainers.image.source": anSource,
			})
		})

		Context("rulesfile deps and requirements", func() {
			When("user provided deps", func() {
				BeforeEach(func() {
					repoName, fullRepoName = randomRulesRepoName(registry, rulesRepoBaseName)
					rulesfile = rulesFileWithDepsAndReq
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--depends-on", dep1, "--depends-on", dep2, "--requires", req, "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})

				AssertSuccesBehaviour([]oci.ArtifactDependency{
					{
						Name:         "myplugin",
						Version:      "1.2.3",
						Alternatives: nil,
					}, {
						Name:    "myplugin1",
						Version: "1.2.3",
						Alternatives: []oci.Dependency{{
							Name:    "otherplugin",
							Version: "3.2.1",
						},
						},
					},
				}, []oci.ArtifactRequirement{
					{
						Name:    "engine_version_semver",
						Version: "0.37.0",
					},
				}, map[string]string{
					"org.opencontainers.image.source": anSource,
				})
			})

			When("parsed from file deps", func() {
				BeforeEach(func() {
					repoName, fullRepoName = randomRulesRepoName(registry, rulesRepoBaseName)
					rulesfile = rulesFileWithDepsAndReq
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})

				AssertSuccesBehaviour([]oci.ArtifactDependency{
					{
						Name:         "cloudtrail",
						Version:      "0.2.3",
						Alternatives: nil,
					}, {
						Name:         "json",
						Version:      "0.2.2",
						Alternatives: nil,
					},
				}, []oci.ArtifactRequirement{
					{
						Name:    "engine_version_semver",
						Version: "0.10.0",
					},
				},
					map[string]string{
						"org.opencontainers.image.source": anSource,
					})
			})

			When("parsed from file deps with alternatives", func() {
				var data = `
- required_plugin_versions:
  - name: k8saudit
    version: 0.7.0
    alternatives:
      - name: k8saudit-eks
        version: 0.4.0
  - name: json
    version: 0.7.0
`

				BeforeEach(func() {
					repoName, fullRepoName = randomRulesRepoName(registry, rulesRepoBaseName)
					tmpDir := GinkgoT().TempDir()
					rulesfile, err = testutils.WriteToTmpFile(data, tmpDir)
					Expect(err).ToNot(HaveOccurred())
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})

				AssertSuccesBehaviour([]oci.ArtifactDependency{
					{
						Name:         "json",
						Version:      "0.7.0",
						Alternatives: nil,
					}, {
						Name:    "k8saudit",
						Version: "0.7.0",
						Alternatives: []oci.Dependency{{
							Name:    "k8saudit-eks",
							Version: "0.4.0",
						},
						},
					},
				}, []oci.ArtifactRequirement{},
					map[string]string{
						"org.opencontainers.image.source": anSource,
					})
			})

			When("no deps at all", func() {
				BeforeEach(func() {
					repoName, fullRepoName = randomRulesRepoName(registry, rulesRepoBaseName)
					rulesfile = rulesfileyaml
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})

				AssertSuccesBehaviour([]oci.ArtifactDependency{}, []oci.ArtifactRequirement{},
					map[string]string{
						"org.opencontainers.image.source": anSource,
					})
			})

			When("user provided requirement", func() {
				BeforeEach(func() {
					repoName, fullRepoName = randomRulesRepoName(registry, rulesRepoBaseName)
					rulesfile = rulesFileWithDepsAndReq
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--requires", req, "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})

				AssertSuccesBehaviour([]oci.ArtifactDependency{
					{
						Name:         "json",
						Version:      "0.2.2",
						Alternatives: nil,
					}, {
						Name:         "cloudtrail",
						Version:      "0.2.3",
						Alternatives: nil,
					},
				}, []oci.ArtifactRequirement{
					{
						Name:    "engine_version_semver",
						Version: "0.37.0",
					},
				},
					map[string]string{
						"org.opencontainers.image.source": anSource,
					})
				It("reqs should be the ones provided by the user", func() {
					Expect(fmt.Sprintf("%s:%s", rulesfileData.Layer.Config.Requirements[0].Name,
						rulesfileData.Layer.Config.Requirements[0].Version)).Should(Equal(req))
				})
			})

			When("requirement parsed from file in semver format", func() {
				BeforeEach(func() {
					repoName, fullRepoName = randomRulesRepoName(registry, rulesRepoBaseName)
					rulesfile = rulesFileWithDepsAndReq
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})

				AssertSuccesBehaviour([]oci.ArtifactDependency{
					{
						Name:         "json",
						Version:      "0.2.2",
						Alternatives: nil,
					}, {
						Name:         "cloudtrail",
						Version:      "0.2.3",
						Alternatives: nil,
					},
				}, []oci.ArtifactRequirement{
					{
						Name:    "engine_version_semver",
						Version: "0.10.0",
					},
				}, map[string]string{
					"org.opencontainers.image.source": anSource,
				})
			})

			When("requirement parsed from file in int format", func() {
				var rulesfileContent = `
- required_engine_version: 10
`
				BeforeEach(func() {
					repoName, fullRepoName = randomRulesRepoName(registry, rulesRepoBaseName)
					tmpDir := GinkgoT().TempDir()
					rulesfile, err = testutils.WriteToTmpFile(rulesfileContent, tmpDir)
					Expect(err).ToNot(HaveOccurred())
					args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
						"--plain-http", "--annotation-source", anSource,
						"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				})

				AssertSuccesBehaviour([]oci.ArtifactDependency{}, []oci.ArtifactRequirement{
					{
						Name:    "engine_version_semver",
						Version: "0.10.0",
					},
				}, map[string]string{
					"org.opencontainers.image.source": anSource,
				})
			})
		})
	})

	Context("failure", func() {
		When("requirement parsed from file -- invalid format (float)", func() {
			var rulesFile = `
- required_engine_version: 10.0
`
			BeforeEach(func() {
				repoName, fullRepoName = randomRulesRepoName(registry, rulesRepoBaseName)
				tmpDir := GinkgoT().TempDir()
				rulesfile, err = testutils.WriteToTmpFile(rulesFile, tmpDir)
				Expect(err).ToNot(HaveOccurred())
				args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
					"--plain-http", "--annotation-source", anSource,
					"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
			})

			It("should fail", func() {
				Expect(err).Should(HaveOccurred())
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta("required_engine_version must be an int or a string respecting " +
					"the semver specification, got type float64")))
			})
		})

		When("requirement parsed from file -- invalid format (not semver)", func() {
			var rulesFile = `
- required_engine_version: 10.0notsemver
`
			BeforeEach(func() {
				repoName, fullRepoName = randomRulesRepoName(registry, rulesRepoBaseName)
				tmpDir := GinkgoT().TempDir()
				rulesfile, err = testutils.WriteToTmpFile(rulesFile, tmpDir)
				Expect(err).ToNot(HaveOccurred())
				args = []string{registryCmd, pushCmd, fullRepoName, rulesfile, "--config", configFile, "--type", "rulesfile", "--version", version,
					"--plain-http", "--annotation-source", anSource,
					"--tag", pushedTags[0], "--tag", pushedTags[1], "--tag", pushedTags[2], "--name", artifactNameInConfigLayer}
				// Set name to the expected one.
				artifactNameInConfigLayer = repoName
				// We expect that latest tag is pushed, so set it in the pushed tags.
				pushedTags = []string{"latest"}
			})

			It("reqs should be the ones provided by the user", func() {
				Expect(err).Should(HaveOccurred())
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta("10.0notsemver must be in semver format: No Major.Minor.Patch elements found")))
			})
		})
	})
})
