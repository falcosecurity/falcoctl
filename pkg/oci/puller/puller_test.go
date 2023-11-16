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

package puller_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

var _ = Describe("Puller", func() {
	const nonExistingArtifact = "non-existing-artifact"
	var (
		puller    *ocipuller.Puller
		plainHTTP = true
		tracker   output.Tracker
	)

	Context("Pull func", func() {
		var (
			ref    string
			OS     string
			ARCH   string
			result *oci.RegistryResult
			err    error
		)
		JustBeforeEach(func() {
			puller = ocipuller.NewPuller(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
			result, err = puller.Pull(ctx, ref, destinationDir, OS, ARCH)
		})

		JustAfterEach(func() {
			result = nil
			err = nil
		})

		Describe("plugin artifact", func() {
			When("non existing artifact", func() {
				BeforeEach(func() {
					ref = nonExistingArtifact
				})

				It("should error", func() {
					Expect(err).Should(HaveOccurred())
					Expect(result).Should(BeNil())
				})
			})

			When("with systems OS and ARCH", func() {
				BeforeEach(func() {
					ref = pluginMultiPlatformRef
					OS = runtime.GOOS
					ARCH = runtime.GOARCH
				})

				It("should succeed", func() {
					Expect(err).Should(BeNil())
					Expect(result).ShouldNot(BeNil())
					Expect(result.Type).Should(Equal(oci.Plugin))
					// Check that config file and plugins exists.
					_, err := os.Stat(filepath.Join(destinationDir, result.Filename))
					Expect(err).ShouldNot(HaveOccurred())
					_, err = os.Stat(filepath.Join(destinationDir, "config"))
					Expect(os.IsNotExist(err)).Should(BeTrue())
					// Remove downloaded files from temporary directory.
					Expect(os.Remove(filepath.Join(destinationDir, result.Filename))).ShouldNot(HaveOccurred())
				})
			})
		})

		Describe("rulesfile artifact", func() {
			When("non existing artifact", func() {
				BeforeEach(func() {
					ref = nonExistingArtifact
				})

				It("should error", func() {
					Expect(err).Should(HaveOccurred())
					Expect(result).Should(BeNil())
				})
			})

			When("rulesfile", func() {
				BeforeEach(func() {
					ref = rulesRef
				})

				It("should succeed", func() {
					Expect(err).Should(BeNil())
					Expect(result).ShouldNot(BeNil())
					Expect(result.Type).Should(Equal(oci.Rulesfile))
					// Check that config file and plugins exists.
					_, err := os.Stat(filepath.Join(destinationDir, result.Filename))
					Expect(err).ShouldNot(HaveOccurred())
					_, err = os.Stat(filepath.Join(destinationDir, "config"))
					Expect(os.IsNotExist(err)).Should(BeTrue())
					// Remove downloaded files from temporary directory.
					Expect(os.Remove(filepath.Join(destinationDir, result.Filename))).ShouldNot(HaveOccurred())
				})
			})
		})

		Describe("artifact without config layer", func() {
			BeforeEach(func() {
				ref = artifactWithuoutConfigRef
			})

			It("should succeed", func() {
				Expect(err).Should(BeNil())
				Expect(result).ShouldNot(BeNil())
				Expect(result.Type).Should(Equal(oci.Rulesfile))
				// Check that config file and plugins exists.
				_, err := os.Stat(filepath.Join(destinationDir, result.Filename))
				Expect(err).ShouldNot(HaveOccurred())
				_, err = os.Stat(filepath.Join(destinationDir, "config"))
				Expect(os.IsNotExist(err)).Should(BeTrue())
				// Remove downloaded files from temporary directory.
				Expect(os.Remove(filepath.Join(destinationDir, result.Filename))).ShouldNot(HaveOccurred())
			})
		})
	})

	Context("PullConfigLayer func", func() {
		var (
			ref      string
			os       string
			arch     string
			cfgLayer []byte
			err      error
		)
		JustBeforeEach(func() {
			puller = ocipuller.NewPuller(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
			cfgLayer, err = puller.PullConfigLayer(ctx, ref, os, arch)
		})

		JustAfterEach(func() {
			cfgLayer = nil
			err = nil
			os = ""
			arch = ""
		})

		When("Artifact does not exist", func() {
			BeforeEach(func() {
				ref = nonExistingArtifact
			})

			It("should error", func() {
				Expect(err).Should(HaveOccurred())
				Expect(cfgLayer).Should(BeNil())
			})
		})

		When("config layer is set", func() {
			BeforeEach(func() {
				ref = pluginMultiPlatformRef
				tokens := strings.Split(testPluginPlatform1, "/")
				os = tokens[0]
				arch = tokens[1]
			})

			It("should get config layer", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(cfgLayer).ShouldNot(BeNil())
			})
		})

		When("config layer is not set", func() {
			BeforeEach(func() {
				ref = artifactWithuoutConfigRef
			})

			It("should get an empty config layer", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(string(cfgLayer)).Should(Equal("{}"))
			})
		})

		When("config layer for linux/arm64", func() {
			BeforeEach(func() {
				ref = pluginMultiPlatformRef
				tokens := strings.Split(testPluginPlatform1, "/")
				os = tokens[0]
				arch = tokens[1]
			})

			It("should get config layer", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(cfgLayer).ShouldNot(BeNil())
			})
		})

		When("config layer artifact without platform", func() {
			BeforeEach(func() {
				ref = rulesRef
				tokens := strings.Split(testPluginPlatform1, "/")
				os = tokens[0]
				arch = tokens[1]
			})

			It("should get config layer", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(cfgLayer).ShouldNot(BeNil())
			})
		})

		When("config layer for non existing platform", func() {
			BeforeEach(func() {
				ref = pluginMultiPlatformRef
				os = "linux"
				arch = "non-existing"
			})

			It("should error", func() {
				Expect(err).Should(HaveOccurred())
				Expect(cfgLayer).Should(BeNil())
			})
		})

	})

	Context("Descriptor func", func() {
		var (
			ref  string
			desc *v1.Descriptor
			err  error
		)
		JustBeforeEach(func() {
			puller = ocipuller.NewPuller(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
			desc, err = puller.Descriptor(ctx, ref)
		})

		JustAfterEach(func() {
			desc = nil
			err = nil
		})

		When("Artifact does not exist", func() {
			BeforeEach(func() {
				ref = nonExistingArtifact
			})

			It("should error", func() {
				Expect(err).Should(HaveOccurred())
				Expect(desc).Should(BeNil())
			})
		})

		When("Artifact is of type plugin", func() {
			BeforeEach(func() {
				ref = pluginMultiPlatformRef
			})

			It("should get descriptor", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(desc).ShouldNot(BeNil())
			})
		})

		When("Artifact is of type rulesfile", func() {
			BeforeEach(func() {
				ref = rulesRef
			})

			It("should get descriptor", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(desc).ShouldNot(BeNil())
			})
		})
	})

	Context("CheckAllowedType func", func() {
		var (
			ref          string
			err          error
			allowedTypes []oci.ArtifactType
		)
		JustBeforeEach(func() {
			puller = ocipuller.NewPuller(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
			err = puller.CheckAllowedType(ctx, ref, runtime.GOOS, runtime.GOARCH, allowedTypes)
		})

		JustAfterEach(func() {
			allowedTypes = nil
			err = nil
		})

		When("allowedTypes is empty", func() {
			BeforeEach(func() {
				ref = nonExistingArtifact
			})

			It("should return nil", func() {
				Expect(err).ShouldNot(HaveOccurred())
			})
		})

		When("Artifact does not exist", func() {
			BeforeEach(func() {
				ref = nonExistingArtifact
				allowedTypes = []oci.ArtifactType{oci.Plugin}
			})

			It("should error", func() {
				Expect(err).Should(HaveOccurred())
			})
		})

		When("Artifact is allowed", func() {
			BeforeEach(func() {
				ref = pluginMultiPlatformRef
				allowedTypes = []oci.ArtifactType{oci.Plugin}
			})

			It("should return nil", func() {
				Expect(err).ShouldNot(HaveOccurred())
			})
		})

		When("Artifact is not allowed", func() {
			BeforeEach(func() {
				ref = rulesRef
				allowedTypes = []oci.ArtifactType{oci.Plugin}
			})

			It("should get descriptor", func() {
				Expect(err).Should(HaveOccurred())
			})
		})
	})
})
