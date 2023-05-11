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

package pull_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/cmd"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	out "github.com/falcosecurity/falcoctl/pkg/output"
)

//nolint:lll,unused // no need to check for line length.
var registryPullUsage = `Usage:
  falcoctl registry pull hostname/repo[:tag|@digest] [flags]

Flags:
  -o, --dest-dir string        destination dir where to save the artifacts(default: current directory)
  -h, --help                   help for pull
      --plain-http             allows interacting with remote registry via plain http requests
      --platform stringArray   os and architecture of the artifact in OS/ARCH format (only for plugins artifacts)

Global Flags:
      --config string     config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --disable-styling   Disable output styling such as spinners, progress bars and colors. Styling is automatically disabled if not attacched to a tty (default false)
  -v, --verbose           Enable verbose logs (default false)

`

//nolint:unused // false positive
var registryPullHelp = `Pull Falco "rulesfile" or "plugin" OCI artifacts from remote registry.

Artifact references are passed as arguments.

A reference is either a simple name or a fully qualified reference ("<registry>/<repository>"),
optionally followed by ":<tag>" (":latest" is assumed by default when no tag is given).

When providing just the name of the artifact, the command will search for the artifacts in
the configured index files, and if found, it will use the registry and repository specified
in the indexes.

Example - Pull artifact "myplugin" for the platform where falcoctl is running (default) in the current working directory (default):
	falcoctl registry pull localhost:5000/myplugin:latest

Example - Pull artifact "myplugin" for platform "linux/arm64" in the current working directory (default):
	falcoctl registry pull localhost:5000/myplugin:latest --platform linux/arm64

Example - Pull artifact "myplugin" for platform "linux/arm64" in "myDir" directory:
	falcoctl registry pull localhost:5000/myplugin:latest --platform linux/arm64 --dest-dir=./myDir

Example - Pull artifact "myrulesfile":
	falcoctl registry pull localhost:5000/myrulesfile:latest
`

//nolint:unused // false positive
var pullAssertFailedBehavior = func(usage, specificError string) {
	It("check that fails and the usage is not printed", func() {
		Expect(err).To(HaveOccurred())
		Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(usage)))
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
	})
}

//nolint:unused // false positive
var registryPullTests = Describe("pull", func() {
	var (
		pusher *ocipusher.Pusher
		ref    string
		config ocipusher.Option
	)

	const (
		// Used as flags for all the test cases.
		registryCmd = "registry"
		pullCmd     = "pull"
		dep1        = "myplugin:1.2.3"
		dep2        = "myplugin1:1.2.3|otherplugin:3.2.1"
		req         = "engine_version:15"
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
			args = []string{registryCmd, pullCmd, "--help"}
		})

		It("should match the saved one", func() {

			Expect(output).Should(gbytes.Say(regexp.QuoteMeta(registryPullHelp)))
		})
	})

	// Here we are testing all the failure cases using both the rulesfile and plugin artifact types.
	// The common logic for the artifacts is tested once using a rulesfile artifact, no need to repeat
	// the same test using a plugin artifact.
	Context("failure", func() {
		var (
			tracker               out.Tracker
			options               []ocipusher.Option
			filePathsAndPlatforms ocipusher.Option
			destDir               string
		)
		const (
			plainHTTP           = true
			testPluginPlatform1 = "linux/amd64"
		)

		When("without artifact", func() {
			BeforeEach(func() {
				args = []string{registryCmd, pullCmd}
			})
			pullAssertFailedBehavior(registryPullUsage, "ERRO: accepts 1 arg(s), received 0")
		})

		When("unreachable registry", func() {
			BeforeEach(func() {
				configDir := GinkgoT().TempDir()
				configFile := filepath.Join(configDir, ".config")
				_, err := os.Create(configFile)
				Expect(err).To(BeNil())
				args = []string{registryCmd, pullCmd, "noregistry/testrules", "--plain-http", "--config", configFile}
			})
			pullAssertFailedBehavior(registryPullUsage, "ERRO: unable to connect to remote registry")
		})

		When("invalid repository", func() {
			newReg := registry + "/wrong:latest"
			BeforeEach(func() {
				configDir := GinkgoT().TempDir()
				configFile := filepath.Join(configDir, ".config")
				_, err := os.Create(configFile)
				Expect(err).To(BeNil())
				args = []string{registryCmd, pullCmd, newReg, "--plain-http", "--config", configFile}
			})
			pullAssertFailedBehavior(registryPullUsage, fmt.Sprintf("ERRO: %s: not found", newReg))
		})

		When("unwritable --dest-dir", func() {
			BeforeEach(func() {
				configDir := GinkgoT().TempDir()
				configFile := filepath.Join(configDir, ".config")
				_, err := os.Create(configFile)
				Expect(err).To(BeNil())
				destDir = GinkgoT().TempDir()
				err = os.Chmod(destDir, 0o555)
				Expect(err).To(BeNil())
				pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
				ref = registry + repoAndTag
				config = ocipusher.WithArtifactConfig(oci.ArtifactConfig{})
				filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{plugintgz}, []string{testPluginPlatform1})
				options = []ocipusher.Option{filePathsAndPlatforms, config}
				result, err := pusher.Push(ctx, oci.Plugin, ref, options...)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())
				args = []string{registryCmd, pullCmd, ref, "--plain-http",
					"--platform", testPluginPlatform1, "--dest-dir", destDir,
					"--config", configFile,
				}
			})

			It("check that fails and the usage is not printed", func() {
				tmp := strings.Split(repoAndTag, "/")
				artNameAndTag := tmp[len(tmp)-1]
				tmp = strings.Split(artNameAndTag, ":")
				artName := tmp[0]
				tag := tmp[1]
				expectedError := fmt.Sprintf(
					"ERRO: unable to pull artifact generic-repo with %s tag from repo %s: failed to create file",
					tag, artName)
				Expect(err).To(HaveOccurred())
				Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(registryPullUsage)))
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(expectedError)))
			})
		})

		When("--dest-dir not present (and parent not writable)", func() {
			BeforeEach(func() {
				configDir := GinkgoT().TempDir()
				configFile := filepath.Join(configDir, ".config")
				_, err := os.Create(configFile)
				Expect(err).To(BeNil())
				baseDir := GinkgoT().TempDir()
				err = os.Chmod(baseDir, 0o555)
				Expect(err).To(BeNil())
				destDir = baseDir + "/dest"
				pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
				ref = registry + repoAndTag
				config = ocipusher.WithArtifactConfig(oci.ArtifactConfig{})
				filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{plugintgz}, []string{testPluginPlatform1})
				options = []ocipusher.Option{filePathsAndPlatforms, config}
				result, err := pusher.Push(ctx, oci.Plugin, ref, options...)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())
				args = []string{registryCmd, pullCmd, ref, "--plain-http",
					"--platform", testPluginPlatform1, "--dest-dir", destDir,
					"--config", configFile,
				}
			})

			It("check that fails and the usage is not printed", func() {
				expectedError := fmt.Sprintf(
					"ERRO: unable to push artifact failed to ensure directories of the target path: mkdir %s: permission denied\n"+
						"ERRO: unable to pull artifact %s with tag %s from repo %s: failed to ensure directories of the target path: mkdir %s: permission denied",
					destDir, artifact, tag, artifact, destDir)
				Expect(err).To(HaveOccurred())
				Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(registryPullUsage)))
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(expectedError)))
			})
		})

		When("wrong digest format", func() {
			wrongDigest := "sha256:06f961b802bc46ee168555f066d28f4f0e9afdf3f88174c1ee6f9de004fc30a0"
			BeforeEach(func() {
				configDir := GinkgoT().TempDir()
				configFile := filepath.Join(configDir, ".config")
				_, err := os.Create(configFile)
				Expect(err).To(BeNil())
				pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
				ref = registry + repoAndTag
				config = ocipusher.WithArtifactConfig(oci.ArtifactConfig{})
				filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{plugintgz}, []string{testPluginPlatform1})
				options = []ocipusher.Option{filePathsAndPlatforms, config}
				result, err := pusher.Push(ctx, oci.Plugin, ref, options...)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())
				ref = registry + repoAndTag + "@" + wrongDigest
				args = []string{registryCmd, pullCmd, ref, "--plain-http",
					"--platform", testPluginPlatform1, "--config", configFile}
			})

			It("check that fails and the usage is not printed", func() {
				expectedError := fmt.Sprintf("ERRO: %s: not found", registry+repo+"@"+wrongDigest)
				Expect(err).To(HaveOccurred())
				Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(registryPullUsage)))
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(expectedError)))
			})
		})

		When("missing repository", func() {
			BeforeEach(func() {
				configDir := GinkgoT().TempDir()
				configFile := filepath.Join(configDir, ".config")
				_, err := os.Create(configFile)
				Expect(err).To(BeNil())
				ref = repoAndTag
				args = []string{registryCmd, pullCmd, ref, "--plain-http", "--config", configFile}
			})

			It("check that fails and the usage is not printed", func() {
				expectedError := fmt.Sprintf("ERRO: cannot extract registry name from ref %q", ref)
				Expect(err).To(HaveOccurred())
				Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(registryPullUsage)))
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(expectedError)))
			})
		})

		When("invalid repository", func() {
			newReg := registry + "/wrong@something"
			BeforeEach(func() {
				configDir := GinkgoT().TempDir()
				configFile := filepath.Join(configDir, ".config")
				_, err := os.Create(configFile)
				Expect(err).To(BeNil())
				args = []string{registryCmd, pullCmd, newReg, "--plain-http", "--config", configFile}
			})
			pullAssertFailedBehavior(registryPullUsage, fmt.Sprintf("ERRO: unable to create new repository with ref %s: "+
				"invalid reference: invalid digest; invalid checksum digest format\n", newReg))
		})

		When("invalid platform", func() {
			BeforeEach(func() {
				configDir := GinkgoT().TempDir()
				configFile := filepath.Join(configDir, ".config")
				_, err := os.Create(configFile)
				Expect(err).To(BeNil())
				pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
				ref = registry + repoAndTag
				config = ocipusher.WithArtifactConfig(oci.ArtifactConfig{})
				filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{plugintgz}, []string{testPluginPlatform1})
				options = []ocipusher.Option{filePathsAndPlatforms, config}
				result, err := pusher.Push(ctx, oci.Plugin, ref, options...)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())
				ref = registry + repoAndTag
				args = []string{registryCmd, pullCmd, ref, "--plain-http",
					"--platform", "linux/unknown", "--config", configFile}
			})

			pullAssertFailedBehavior(registryPullUsage, "not found: no matching manifest was found in the manifest list")
		})

	})

})
