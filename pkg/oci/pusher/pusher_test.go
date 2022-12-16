// Copyright 2022 The Falco Authors
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

package pusher_test

import (
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

var _ = Describe("Pusher", func() {
	var (
		pusher                *ocipusher.Pusher
		tracker               output.Tracker
		ref                   string
		filePathsAndPlatforms ocipusher.Option
		filePaths             ocipusher.Option
		tags                  ocipusher.Option
		dependencies          ocipusher.Option
		annotationSource      ocipusher.Option
		options               []ocipusher.Option
		repoAndTag            = "/generic-repo:tag"
		repo                  registry.Repository
		result                *oci.RegistryResult
		artifactType          oci.ArtifactType
		listTags              []string
		fetchedTags           []string
		sourceKey             = v1.AnnotationSource
		sourceValue           string
		plainHTTP             = true
		err                   error
	)
	JustBeforeEach(func() {
		pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
		ref = localRegistryHost + repoAndTag
		result, err = pusher.Push(ctx, artifactType, ref, options...)
	})

	JustAfterEach(func() {
		plainHTTP = true
		repoAndTag = "/generic-repo:tag"
	})

	Context("handling plugin artifacts", func() {
		BeforeEach(func() {
			artifactType = oci.Plugin
		})
		Context("without platform", func() {
			BeforeEach(func() {
				filePathsAndPlatforms = ocipusher.WithFilepaths([]string{testPluginTarball})
				options = []ocipusher.Option{filePathsAndPlatforms}
			})
			It("should error", func() {
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, ocipusher.ErrInvalidPlatformFormat)).To(BeTrue())
				Expect(result).To(BeNil())
			})
		})

		Context("with dependencies", func() {
			BeforeEach(func() {
				filePathsAndPlatforms = ocipusher.WithFilepaths([]string{testPluginTarball})
				dependencies = ocipusher.WithDependencies([]string{"myDep:1.2.3"}...)
				options = []ocipusher.Option{filePathsAndPlatforms, dependencies}
			})
			It("should error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("expecting no dependencies for plugin artifacts but received"))
				Expect(result).To(BeNil())
			})
		})

		Context("with filepaths and platform", func() {
			When("mismatch between filepath and platform numbers", func() {
				BeforeEach(func() {
					filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{testPluginTarball}, []string{testPluginPlatform1, "mismatch"})
					options = append(options, filePathsAndPlatforms)
				})
				It("should error", func() {
					Expect(err).To(HaveOccurred())
					Expect(errors.Is(err, ocipusher.ErrMismatchFilepathAndPlatform)).To(BeTrue())
					Expect(result).To(BeNil())
				})
			})

			When("correct number of filepaths and platforms", func() {
				Context("pushing only one plugin: 1 filepath, 1 platform with multiple tags and with annotation source", func() {
					BeforeEach(func() {
						// Additional tags to be added to the artifact.
						listTags = []string{"tag1", "tag2", "tag3"}
						tags = ocipusher.WithTags(listTags...)
						// One version of the artifact for a single platform.
						filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{testPluginTarball}, []string{testPluginPlatform1})
						// Adding annotation source to the index.
						sourceValue = "https://plugins/source/test"
						annotationSource = ocipusher.WithAnnotationSource(sourceValue)
						options = []ocipusher.Option{tags, filePathsAndPlatforms, annotationSource}

						// Repo and default tag for the artifact
						repoAndTag = "/plugin-test:latest"
						repo, err = localRegistry.Repository(ctx, "plugin-test")
						Expect(err).To(BeNil())
					})

					It("should succeed", func() {
						Expect(err).ToNot(HaveOccurred())
						Expect(result).ToNot(BeNil())
						d, reader, err := repo.FetchReference(ctx, ref)
						Expect(err).ToNot(HaveOccurred())
						index, err := imageIndexFromReader(reader)
						Expect(err).ToNot(HaveOccurred())
						// Being the artifact of type plugin we expect that the retrieved descriptor is of type image index.
						Expect(d.MediaType).To(Equal(v1.MediaTypeImageIndex))
						Expect(d.Digest.String()).To(Equal(result.Digest))
						Expect(index.Manifests).To(HaveLen(1))
						Expect(fmt.Sprintf("%s/%s", index.Manifests[0].Platform.OS, index.Manifests[0].Platform.Architecture)).To(Equal(testPluginPlatform1))

						// Check that annotation source is present and contains right value.
						Expect(index.Annotations).To(HaveKeyWithValue(sourceKey, sourceValue))

						// Check that the tags have also been pushed.
						err = repo.Tags(ctx, "", func(tags []string) error {
							fetchedTags = nil
							for i := range tags {
								fetchedTags = append(fetchedTags, tags[i])
							}
							return nil
						})
						Expect(err).ToNot(HaveOccurred())
						// It must have the initial tag + the other three tags.
						Expect(fetchedTags).To(HaveLen(4))
						Expect(fetchedTags).To(ContainElements(listTags[0], listTags[1], listTags[2]))
					})
				})

				Context("pushing multiple flavors of plugin: 3 filepath, 3 platform without tag", func() {
					BeforeEach(func() {
						// Different files, one for each platform.
						filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{testPluginTarball, testPluginTarball, testPluginTarball},
							[]string{testPluginPlatform1, testPluginPlatform2, testPluginPlatform3})
						options = []ocipusher.Option{filePathsAndPlatforms}
						// Pushing the artifact without an explicit tag, the default tag (latest) will be added by the pusher.
						repoAndTag = "/plugin-test-three-flavors"
						repo, err = localRegistry.Repository(ctx, "plugin-test-three-flavors")
						Expect(err).To(BeNil())
					})

					It("should succeed", func() {
						Expect(err).ToNot(HaveOccurred())
						Expect(result).ToNot(BeNil())
						// Since we have not specified a tag for the artifact we expect that the pusher will add it.
						d, reader, err := repo.FetchReference(ctx, ref+":latest")
						Expect(err).ToNot(HaveOccurred())
						index, err := imageIndexFromReader(reader)
						Expect(err).ToNot(HaveOccurred())
						// Being the artifact of type plugin we expect that the retrieved descriptor is of type image index.
						Expect(d.MediaType).To(Equal(v1.MediaTypeImageIndex))
						Expect(d.Digest.String()).To(Equal(result.Digest))
						Expect(index.Manifests).To(HaveLen(3))
						Expect(fmt.Sprintf("%s/%s", index.Manifests[0].Platform.OS, index.Manifests[0].Platform.Architecture)).To(Equal(testPluginPlatform1))
						Expect(fmt.Sprintf("%s/%s", index.Manifests[1].Platform.OS, index.Manifests[1].Platform.Architecture)).To(Equal(testPluginPlatform2))
						Expect(fmt.Sprintf("%s/%s", index.Manifests[2].Platform.OS, index.Manifests[2].Platform.Architecture)).To(Equal(testPluginPlatform3))
					})
				})

			})

		})
	})

	Context("handling rulesfile artifacts", func() {
		BeforeEach(func() {
			artifactType = oci.Rulesfile
		})

		Context("with filepaths", func() {
			When("only one rulesfile is given", func() {
				BeforeEach(func() {
					filePaths = ocipusher.WithFilepaths([]string{testRuleTarball})
					options = []ocipusher.Option{filePaths}
					// Repo and default tag for the artifact
					repoAndTag = "/rulesfile-test:1.2.3"
					repo, err = localRegistry.Repository(ctx, "rulesfile-test")
					Expect(err).To(BeNil())
				})
				It("should succeed", func() {
					Expect(err).ToNot(HaveOccurred())
					Expect(result).ToNot(BeNil())
					d, reader, err := repo.FetchReference(ctx, ref)
					Expect(err).ToNot(HaveOccurred())
					manifest, err := manifestFromReader(reader)
					Expect(err).ToNot(HaveOccurred())
					// Being the artifact of type rulesfile we expect that the retrieved descriptor is of type manifest.
					Expect(d.MediaType).To(Equal(v1.MediaTypeImageManifest))
					Expect(d.Digest.String()).To(Equal(result.Digest))
					// It must have only one layer since no config layer is configured.
					Expect(manifest.Layers).To(HaveLen(1))
					// It must have the config type for the rulesfile.
					Expect(manifest.Config.MediaType).To(Equal(oci.FalcoRulesfileConfigMediaType))
				})
			})

			When("multiple rulesfile are given", func() {
				BeforeEach(func() {
					filePaths = ocipusher.WithFilepaths([]string{testRuleTarball, testRuleTarball})
					options = []ocipusher.Option{filePaths}
					// Repo and default tag for the artifact
					repoAndTag = "/rulesfile-test:1.2.4"
					repo, err = localRegistry.Repository(ctx, "rulesfile-test")
					Expect(err).To(BeNil())
				})
				It("should error", func() {
					Expect(err).To(HaveOccurred())
					Expect(errors.Is(err, ocipusher.ErrInvalidNumberRulesfiles)).To(BeTrue())
					Expect(result).To(BeNil())
				})
			})
		})

		Context("with dependencies", func() {
			When("valid dependencies and default tag", func() {
				BeforeEach(func() {
					filePaths = ocipusher.WithFilepaths([]string{testRuleTarball})
					dependencies = ocipusher.WithDependencies([]string{"dep1:1.2.3", "dep2:2.3.1"}...)
					options = []ocipusher.Option{filePaths, dependencies}
					// Repo and default tag for the artifact
					repoAndTag = "/rulesfile-dependencies"
					repo, err = localRegistry.Repository(ctx, "rulesfile-dependencies")
					Expect(err).To(BeNil())
				})
				It("should succeed", func() {
					Expect(err).ToNot(HaveOccurred())
					Expect(result).ToNot(BeNil())
					d, reader, err := repo.FetchReference(ctx, ref+":latest")
					Expect(err).ToNot(HaveOccurred())
					manifest, err := manifestFromReader(reader)
					Expect(err).ToNot(HaveOccurred())
					// Being the artifact of type rulesfile we expect that the retrieved descriptor is of type manifest.
					Expect(d.MediaType).To(Equal(v1.MediaTypeImageManifest))
					Expect(d.Digest.String()).To(Equal(result.Digest))
					// It must have only one layer since no config layer is configured.
					Expect(manifest.Layers).To(HaveLen(1))
					// It must have the config type for the rulesfile.
					Expect(manifest.Config.MediaType).To(Equal(oci.FalcoRulesfileConfigMediaType))
					// Fetch the config layer
					reader, err = repo.Fetch(ctx, manifest.Config)
					Expect(err).ToNot(HaveOccurred())
					dep, err := dependenciesFromReader(reader)
					Expect(err).ToNot(HaveOccurred())
					Expect(dep).ToNot(BeNil())
					// Check that we have the same number of deps that we set before.
					Expect(len(dep.Dependencies)).To(Equal(2))
				})
			})

			When("invalid dependencies", func() {
				BeforeEach(func() {
					filePaths = ocipusher.WithFilepaths([]string{testRuleTarball})
					dependencies = ocipusher.WithDependencies([]string{"dep1:wrongdep"}...)
					options = []ocipusher.Option{filePaths, dependencies}
				})
				It("should error", func() {
					Expect(err).To(HaveOccurred())
					Expect(errors.Is(err, ocipusher.ErrInvalidDependenciesFormat)).To(BeTrue())
					Expect(result).To(BeNil())
				})
			})
		})

		Context("with multiple tags", func() {
			BeforeEach(func() {
				// Additional tags to be added to the artifact.
				listTags = []string{"tag1", "tag2", "tag3"}
				tags = ocipusher.WithTags(listTags...)
				filePaths = ocipusher.WithFilepaths([]string{testRuleTarball})
				options = []ocipusher.Option{filePaths, tags}
				// Repo and default tag for the artifact
				repoAndTag = "/rulesfile-multiple-tags:latest"
				repo, err = localRegistry.Repository(ctx, "rulesfile-multiple-tags")
				Expect(err).To(BeNil())
			})

			It("should succeed", func() {
				Expect(err).ToNot(HaveOccurred())
				Expect(result).ToNot(BeNil())
				err = repo.Tags(ctx, "", func(tags []string) error {
					fetchedTags = nil
					for i := range tags {
						fetchedTags = append(fetchedTags, tags[i])
					}
					return nil
				})
				Expect(err).ToNot(HaveOccurred())
				// It must have the initial tag + the other three tags.
				Expect(fetchedTags).To(HaveLen(4))
				Expect(fetchedTags).To(ContainElements(listTags[0], listTags[1], listTags[2]))
			})
		})
	})

	Context("generic error handling", func() {
		When("file does not exist", func() {
			BeforeEach(func() {
				filePaths = ocipusher.WithFilepaths([]string{"../not/existing.file"})
				options = []ocipusher.Option{filePaths}
			})
			It("should error", func() {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("unable to store artifact"))
				Expect(result).To(BeNil())
			})
		})

		When("invalid artifact reference", func() {
			BeforeEach(func() {
				filePaths = ocipusher.WithFilepaths([]string{testRuleTarball})
				options = []ocipusher.Option{filePaths}
				// Repo and default tag for the artifact
				repoAndTag = "/Invalid:Ref:Artifact"
			})
			It("should error", func() {
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, errdef.ErrInvalidReference)).To(BeTrue())
				Expect(result).To(BeNil())
			})
		})

		When("generic error on remote repo operation", func() {
			BeforeEach(func() {
				filePaths = ocipusher.WithFilepaths([]string{testRuleTarball})
				options = []ocipusher.Option{filePaths}
				// This will cause operations on remote repo to fail.
				plainHTTP = false
			})
			It("should error", func() {
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})
		})
	})
})
