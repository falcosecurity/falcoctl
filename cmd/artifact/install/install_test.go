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

package install_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

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
var artifactInstallUsage = `Usage:
  falcoctl artifact install [ref1 [ref2 ...]] [flags]

Flags:
      --allowed-types ArtifactTypeSlice   list of artifact types that can be installed. If not specified or configured, all types are allowed.
                                          It accepts comma separated values or it can be repeated multiple times.
                                          Examples:
                                                --allowed-types="rulesfile,plugin"
                                                --allowed-types=rulesfile --allowed-types=plugin
  -h, --help                              help for install
      --plain-http                        allows interacting with remote registry via plain http requests
      --plugins-dir string                directory where to install plugins. (default "/usr/share/falco/plugins")
      --resolve-deps                      whether this command should resolve dependencies or not (default true)
      --rulesfiles-dir string             directory where to install rules. (default "/etc/falco")

Global Flags:
      --config string     config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --log-format string   Set formatting for logs (color, text, json) (default "color")
      --log-level string    Set level for logs (info, warn, debug, trace) (default "info")

`

//nolint:unused // false positive
var artifactInstallHelp = `This command allows you to install one or more given artifacts.

Artifact references and flags are passed as arguments through:
- command line options
- environment variables
- configuration file
The arguments passed through these different modalities are prioritized in the following order:
command line options, environment variables, and finally the configuration file. This means that
if an argument is passed through multiple modalities, the value set in the command line options
will take precedence over the value set in environment variables, which will in turn take precedence
over the value set in the configuration file.
Please note that when passing multiple artifact references via an environment variable, they must be
separated by a semicolon ';'. Other arguments, if passed through environment variables, should start
with "FALCOCTL_" and be followed by the hierarchical keys used in the configuration file separated by
an underscore "_".

A reference is either a simple name or a fully qualified reference ("<registry>/<repository>"), 
optionally followed by ":<tag>" (":latest" is assumed by default when no tag is given).

When providing just the name of the artifact, the command will search for the artifacts in 
the configured index files, and if found, it will use the registry and repository specified 
in the indexes.

Example - Install "latest" tag of "k8saudit-rules" artifact by relying on index metadata:
	falcoctl artifact install k8saudit-rules

Example - Install all updates from "k8saudit-rules" 0.5.x release series:
	falcoctl artifact install k8saudit-rules:0.5

Example - Install "cloudtrail" plugins using a fully qualified reference:
	falcoctl artifact install ghcr.io/falcosecurity/plugins/ruleset/k8saudit:latest
`

//nolint:unused // false positive
var correctIndexConfig = `indexes:
- name: falcosecurity
  url: https://falcosecurity.github.io/falcoctl/index.yaml
`

//nolint:unused // false positive
var installAssertFailedBehavior = func(usage, specificError string) {
	It("check that fails and the usage is not printed", func() {
		Expect(err).To(HaveOccurred())
		Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(usage)))
		Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
	})
}

//nolint:unused // false positive
var artifactInstallTests = Describe("install", func() {
	var (
		pusher *ocipusher.Pusher
		ref    string
		config ocipusher.Option
	)

	const (
		// Used as flags for all the test cases.
		artifactCmd = "artifact"
		installCmd  = "install"
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
			args = []string{artifactCmd, installCmd, "--help"}
		})

		It("should match the saved one", func() {
			Expect(output).Should(gbytes.Say(regexp.QuoteMeta(artifactInstallHelp)))
		})
	})

	Context("failure", func() {
		var (
			tracker               out.Tracker
			options               []ocipusher.Option
			filePathsAndPlatforms ocipusher.Option
			filePaths             ocipusher.Option
			destDir               string
		)
		const (
			plainHTTP           = true
			testPluginPlatform1 = "linux/amd64"
		)

		When("without artifact", func() {
			BeforeEach(func() {
				configDir := GinkgoT().TempDir()
				configFile := filepath.Join(configDir, ".config")
				_, err := os.Create(configFile)
				Expect(err).To(BeNil())
				args = []string{artifactCmd, installCmd, "--config", configFile}
			})
			installAssertFailedBehavior(artifactInstallUsage,
				"ERROR no artifacts to install, please configure artifacts or pass them as arguments to this command")
		})

		When("unreachable registry", func() {
			BeforeEach(func() {
				configDir := GinkgoT().TempDir()
				configFile := filepath.Join(configDir, ".config")
				_, err := os.Create(configFile)
				Expect(err).To(BeNil())
				args = []string{artifactCmd, installCmd, "noregistry/testrules", "--plain-http", "--config", configFile}
			})
			installAssertFailedBehavior(artifactInstallUsage, `ERROR unable to get manifest: unable to fetch reference`)
		})

		When("invalid repository", func() {
			newReg := registry + "/wrong:latest"
			BeforeEach(func() {
				configDir := GinkgoT().TempDir()
				configFile := filepath.Join(configDir, ".config")
				_, err := os.Create(configFile)
				Expect(err).To(BeNil())
				args = []string{artifactCmd, installCmd, newReg, "--plain-http", "--config", configFile}
			})
			installAssertFailedBehavior(artifactInstallUsage, fmt.Sprintf("ERROR unable to get manifest: unable to fetch reference %q", newReg))
		})

		When("with disallowed types (rulesfile)", func() {
			BeforeEach(func() {
				baseDir := GinkgoT().TempDir()
				configFilePath := baseDir + "/config.yaml"
				content := []byte(correctIndexConfig)
				err := os.WriteFile(configFilePath, content, 0o644)
				Expect(err).To(BeNil())

				// push plugin
				pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
				ref = registry + repoAndTag
				config = ocipusher.WithArtifactConfig(oci.ArtifactConfig{
					Name:    "plugin1",
					Version: "0.0.1",
				})
				filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{plugintgz}, []string{testPluginPlatform1})
				options = []ocipusher.Option{filePathsAndPlatforms, config}
				result, err := pusher.Push(ctx, oci.Plugin, ref, options...)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())
				ref = registry + repoAndTag
				Expect(err).To(BeNil())
				args = []string{artifactCmd, installCmd, ref, "--plain-http",
					"--config", configFilePath, "--allowed-types", "rulesfile"}
			})

			installAssertFailedBehavior(artifactInstallUsage, "ERROR cannot download artifact of type \"plugin\": type not permitted")
		})

		When("with disallowed types (plugin)", func() {
			BeforeEach(func() {
				baseDir := GinkgoT().TempDir()
				configFilePath := baseDir + "/config.yaml"
				content := []byte(correctIndexConfig)
				err := os.WriteFile(configFilePath, content, 0o644)
				Expect(err).To(BeNil())

				// push rulesfile
				pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
				ref = registry + repoAndTag
				config = ocipusher.WithArtifactConfig(oci.ArtifactConfig{
					Name:    "rules1",
					Version: "0.0.1",
				})
				filePaths = ocipusher.WithFilepaths([]string{rulesfiletgz})
				options = []ocipusher.Option{filePaths, config}
				result, err := pusher.Push(ctx, oci.Rulesfile, ref, options...)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())
				ref = registry + repoAndTag
				Expect(err).To(BeNil())
				args = []string{artifactCmd, installCmd, ref, "--plain-http",
					"--config", configFilePath, "--allowed-types", "plugin"}
			})

			installAssertFailedBehavior(artifactInstallUsage, "ERROR cannot download artifact of type \"rulesfile\": type not permitted")
		})

		When("an unknown type is used", func() {
			wrongType := "mywrongtype"
			BeforeEach(func() {
				baseDir := GinkgoT().TempDir()
				configFilePath := baseDir + "/config.yaml"
				content := []byte(correctIndexConfig)
				err := os.WriteFile(configFilePath, content, 0o644)
				Expect(err).To(BeNil())

				// push rulesfile
				pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
				ref = registry + repoAndTag
				config = ocipusher.WithArtifactConfig(oci.ArtifactConfig{
					Name:    "rules1",
					Version: "0.0.1",
				})
				filePaths = ocipusher.WithFilepaths([]string{rulesfiletgz})
				options = []ocipusher.Option{filePaths, config}
				result, err := pusher.Push(ctx, oci.Rulesfile, ref, options...)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())
				ref = registry + repoAndTag
				Expect(err).To(BeNil())
				args = []string{artifactCmd, installCmd, ref, "--plain-http",
					"--config", configFilePath, "--allowed-types", "plugin," + wrongType}
			})

			installAssertFailedBehavior(artifactInstallUsage, fmt.Sprintf("ERROR invalid argument \"plugin,%s\" for \"--allowed-types\" flag: "+
				"not valid token %q: must be one of \"rulesfile\", \"plugin\"", wrongType, wrongType))
		})

		When("--plugins-dir is not writable", func() {
			BeforeEach(func() {
				destDir = GinkgoT().TempDir()
				err = os.Chmod(destDir, 0o555)
				Expect(err).To(BeNil())
				baseDir := GinkgoT().TempDir()
				configFilePath := baseDir + "/config.yaml"
				content := []byte(correctIndexConfig)
				err := os.WriteFile(configFilePath, content, 0o644)
				Expect(err).To(BeNil())

				// push plugin
				pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
				ref = registry + repoAndTag
				config = ocipusher.WithArtifactConfig(oci.ArtifactConfig{
					Name:    "plugin1",
					Version: "0.0.1",
				})
				filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{plugintgz}, []string{testPluginPlatform1})
				options = []ocipusher.Option{filePathsAndPlatforms, config}
				result, err := pusher.Push(ctx, oci.Plugin, ref, options...)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())
				ref = registry + repoAndTag
				Expect(err).To(BeNil())
				args = []string{artifactCmd, installCmd, ref, "--plain-http",
					"--config", configFilePath, "--plugins-dir", destDir}
			})

			It("check that fails and the usage is not printed", func() {
				expectedError := fmt.Sprintf("ERROR cannot use directory %q "+
					"as install destination: %s is not writable", destDir, destDir)
				Expect(err).To(HaveOccurred())
				Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(artifactInstallUsage)))
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(expectedError)))
			})
		})

		When("--plugins-dir is not present", func() {
			BeforeEach(func() {
				destDir = GinkgoT().TempDir()
				err = os.Remove(destDir)
				Expect(err).To(BeNil())
				baseDir := GinkgoT().TempDir()
				configFilePath := baseDir + "/config.yaml"
				content := []byte(correctIndexConfig)
				err := os.WriteFile(configFilePath, content, 0o644)
				Expect(err).To(BeNil())

				// push plugin
				pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
				ref = registry + repoAndTag
				config = ocipusher.WithArtifactConfig(oci.ArtifactConfig{
					Name:    "plugin1",
					Version: "0.0.1",
				})
				filePathsAndPlatforms = ocipusher.WithFilepathsAndPlatforms([]string{plugintgz}, []string{testPluginPlatform1})
				options = []ocipusher.Option{filePathsAndPlatforms, config}
				result, err := pusher.Push(ctx, oci.Plugin, ref, options...)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())
				ref = registry + repoAndTag
				Expect(err).To(BeNil())
				args = []string{artifactCmd, installCmd, ref, "--plain-http",
					"--config", configFilePath, "--plugins-dir", destDir}
			})

			It("check that fails and the usage is not printed", func() {
				expectedError := fmt.Sprintf("ERROR cannot use directory %q "+
					"as install destination: %s doesn't exists", destDir, destDir)
				Expect(err).To(HaveOccurred())
				Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(artifactInstallUsage)))
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(expectedError)))
			})
		})

		When("--rulesfile-dir is not writable", func() {
			BeforeEach(func() {
				destDir = GinkgoT().TempDir()
				err = os.Chmod(destDir, 0o555)
				Expect(err).To(BeNil())
				baseDir := GinkgoT().TempDir()
				configFilePath := baseDir + "/config.yaml"
				content := []byte(correctIndexConfig)
				err := os.WriteFile(configFilePath, content, 0o644)
				Expect(err).To(BeNil())

				// push plugin
				pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
				ref = registry + repoAndTag
				config = ocipusher.WithArtifactConfig(oci.ArtifactConfig{
					Name:    "rules1",
					Version: "0.0.1",
				})
				filePaths = ocipusher.WithFilepaths([]string{rulesfiletgz})
				options = []ocipusher.Option{filePaths, config}
				result, err := pusher.Push(ctx, oci.Rulesfile, ref, options...)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())
				ref = registry + repoAndTag
				Expect(err).To(BeNil())
				args = []string{artifactCmd, installCmd, ref, "--plain-http",
					"--config", configFilePath, "--rulesfiles-dir", destDir}
			})

			It("check that fails and the usage is not printed", func() {
				expectedError := fmt.Sprintf("ERROR cannot use directory %q "+
					"as install destination: %s is not writable", destDir, destDir)
				Expect(err).To(HaveOccurred())
				Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(artifactInstallUsage)))
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(expectedError)))
			})
		})

		When("not existing --plugins-dir", func() {
			BeforeEach(func() {
				destDir = GinkgoT().TempDir()
				err = os.Remove(destDir)
				Expect(err).To(BeNil())
				baseDir := GinkgoT().TempDir()
				configFilePath := baseDir + "/config.yaml"
				content := []byte(correctIndexConfig)
				err := os.WriteFile(configFilePath, content, 0o644)
				Expect(err).To(BeNil())

				// push plugin
				pusher = ocipusher.NewPusher(authn.NewClient(authn.WithCredentials(&auth.EmptyCredential)), plainHTTP, tracker)
				ref = registry + repoAndTag
				config = ocipusher.WithArtifactConfig(oci.ArtifactConfig{
					Name:    "rules1",
					Version: "0.0.1",
				})
				filePathsAndPlatforms = ocipusher.WithFilepaths([]string{rulesfiletgz})
				options = []ocipusher.Option{filePaths, config}
				result, err := pusher.Push(ctx, oci.Rulesfile, ref, options...)
				Expect(err).To(BeNil())
				Expect(result).ToNot(BeNil())
				ref = registry + repoAndTag
				Expect(err).To(BeNil())
				args = []string{artifactCmd, installCmd, ref, "--plain-http",
					"--config", configFilePath, "--rulesfiles-dir", destDir}
			})

			It("check that fails and the usage is not printed", func() {
				expectedError := fmt.Sprintf("ERROR cannot use directory %q "+
					"as install destination: %s doesn't exists", destDir, destDir)
				Expect(err).To(HaveOccurred())
				Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(artifactInstallUsage)))
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(expectedError)))
			})
		})

	})

})
