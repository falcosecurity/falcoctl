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
//

package manifest_test

import (
	"regexp"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"

	"github.com/falcosecurity/falcoctl/cmd"
)

var usage = `Usage:
  falcoctl artifact manifest [ref] [flags]

Flags:
  -h, --help              help for manifest
      --plain-http        allows interacting with remote registry via plain http requests
      --platform string   os and architecture of the artifact in OS/ARCH format (default "linux/amd64")

Global Flags:
      --config string       config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --log-format string   Set formatting for logs (color, text, json) (default "color")
      --log-level string    Set level for logs (info, warn, debug, trace) (default "info")
`

var help = `Get the manifest layer of an artifact

Usage:
  falcoctl artifact manifest [ref] [flags]

Flags:
  -h, --help              help for manifest
      --plain-http        allows interacting with remote registry via plain http requests
      --platform string   os and architecture of the artifact in OS/ARCH format (default "linux/amd64")

Global Flags:
      --config string       config file to be used for falcoctl (default "/etc/falcoctl/falcoctl.yaml")
      --log-format string   Set formatting for logs (color, text, json) (default "color")
      --log-level string    Set level for logs (info, warn, debug, trace) (default "info")
`

var _ = Describe("Manifest", func() {
	const (
		artifactCmd  = "artifact"
		manifestCmd  = "manifest"
		plaingHTTP   = "--plain-http"
		configFlag   = "--config"
		platformFlag = "--platform"
	)

	var (
		err       error
		args      []string
		configDir string
	)

	var assertFailedBehavior = func(usage, specificError string) {
		It("check that fails and the usage is not printed", func() {
			Expect(err).To(HaveOccurred())
			Expect(output).ShouldNot(gbytes.Say(regexp.QuoteMeta(usage)))
			Expect(output).Should(gbytes.Say(regexp.QuoteMeta(specificError)))
		})
	}

	JustBeforeEach(func() {
		configDir = GinkgoT().TempDir()
		rootCmd = cmd.New(ctx, opt)
		err = executeRoot(args)
	})

	JustAfterEach(func() {
		err = nil
		Expect(output.Clear()).ShouldNot(HaveOccurred())
		args = nil
	})

	Context("help message", func() {
		BeforeEach(func() {
			args = []string{artifactCmd, manifestCmd, "--help"}
		})

		It("should match the saved one", func() {
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(output.Contents())).Should(Equal(help))
		})
	})

	Context("wrong number of arguments", func() {
		When("number of arguments equal to 0", func() {
			BeforeEach(func() {
				args = []string{artifactCmd, manifestCmd}
			})

			assertFailedBehavior(usage, "ERROR accepts 1 arg(s), received 0 ")
		})

		When("number of arguments equal to 2", func() {
			BeforeEach(func() {
				args = []string{artifactCmd, manifestCmd, "arg1", "arg2", configFlag, configDir}
			})

			assertFailedBehavior(usage, "ERROR accepts 1 arg(s), received 2 ")
		})
	})

	Context("failure", func() {
		When("unreachable/non existing registry", func() {
			BeforeEach(func() {
				args = []string{artifactCmd, manifestCmd, "noregistry/noartifact", plaingHTTP, configFlag, configDir}
			})

			assertFailedBehavior(usage, "ERROR unable to fetch reference \"noregistry/noartifact:latest\"")
		})

		When("non existing repository", func() {
			BeforeEach(func() {
				args = []string{artifactCmd, manifestCmd, localRegistryHost + "/noartifact", plaingHTTP, configFlag, configDir}
			})

			assertFailedBehavior(usage, "noartifact:latest: not found")
		})

		When("non parsable reference", func() {
			BeforeEach(func() {
				args = []string{artifactCmd, manifestCmd, " ", plaingHTTP, configFlag, configDir}
			})

			assertFailedBehavior(usage, "ERROR cannot find   among the configured indexes, skipping ")
		})

		When("no manifest for given platform", func() {
			BeforeEach(func() {
				args = []string{artifactCmd, manifestCmd, pluginMultiPlatformRef, plaingHTTP, configFlag, configDir, platformFlag, "linux/wrong"}
			})
			assertFailedBehavior(usage, "ERROR unable to find a manifest matching the given platform: linux/wrong")
		})
	})

	Context("success", func() {
		When("without image index and no platform (rulesfiles)", func() {
			BeforeEach(func() {
				args = []string{artifactCmd, manifestCmd, rulesRef, plaingHTTP, configFlag, configDir}
			})

			It("should success", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.cncf.falco.rulesfile.config.v1+json","digest":"sha256:c329db306d80e7f1e3a5df28bb7d75a0a1545ad1e8f717a4ab4534a3d558affa","size":86},"layers":[{"mediaType":"application/vnd.cncf.falco.rulesfile.layer.v1+tar.gz","digest":"sha256:8ed676f9801d987a26854827beb176eb9164dec3b09a714406348fe1096f7c6c","size":2560,"annotations":{"org.opencontainers.image.title":"rules.tar.gz"}}],"annotations":{"org.opencontainers.image.created":`))) //nolint:lll //testing purpose
			})
		})

		When("no platform flag", func() {
			BeforeEach(func() {
				args = []string{artifactCmd, manifestCmd, pluginMultiPlatformRef, plaingHTTP, configFlag, configDir}
			})

			It("should success getting the platform where tests are running", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(
					`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.cncf.falco.plugin.config.v1+json","digest":"sha256:39ae8c14fd9ef38d0f1836ba7be71627023ce615f165c3663586a325eee04724","size":164},"layers":[{"mediaType":"application/vnd.cncf.falco.plugin.layer.v1+tar.gz","digest":"sha256:45a192b10e9bbfc82f4216b071afefd7fba56e02e856e37186430d40160e5d64","size":6659921,"annotations":{"org.opencontainers.image.title":"plugin.tar.gz"}}],"annotations":{"org.opencontainers.image.created":`))) //nolint:lll //testing purpose
			})
		})

		When("with valid platform", func() {
			BeforeEach(func() {
				args = []string{artifactCmd, manifestCmd, pluginMultiPlatformRef, plaingHTTP, configFlag, configDir, platformFlag, testPluginPlatform3}
			})

			It("should success", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(
					`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.cncf.falco.plugin.config.v1+json","digest":"sha256:39ae8c14fd9ef38d0f1836ba7be71627023ce615f165c3663586a325eee04724","size":164},"layers":[{"mediaType":"application/vnd.cncf.falco.plugin.layer.v1+tar.gz","digest":"sha256:45a192b10e9bbfc82f4216b071afefd7fba56e02e856e37186430d40160e5d64","size":6659921,"annotations":{"org.opencontainers.image.title":"plugin.tar.gz"}}],"annotations":{"org.opencontainers.image.created":`))) //nolint:lll //testing purpose
			})
		})

		When("with non existing platform for artifacts without platforms", func() {
			BeforeEach(func() {
				args = []string{artifactCmd, manifestCmd, rulesRef, plaingHTTP, configFlag, configDir, platformFlag, testPluginPlatform3}
			})

			It("should success and ignore the platform flag", func() {
				Expect(err).ShouldNot(HaveOccurred())
				Expect(output).Should(gbytes.Say(regexp.QuoteMeta(
					`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.cncf.falco.rulesfile.config.v1+json","digest":"sha256:c329db306d80e7f1e3a5df28bb7d75a0a1545ad1e8f717a4ab4534a3d558affa","size":86},"layers":[{"mediaType":"application/vnd.cncf.falco.rulesfile.layer.v1+tar.gz","digest":"sha256:8ed676f9801d987a26854827beb176eb9164dec3b09a714406348fe1096f7c6c","size":2560,"annotations":{"org.opencontainers.image.title":"rules.tar.gz"}}],"annotations":{"org.opencontainers.image.created":`))) //nolint:lll //testing purpose
			})
		})
	})
})
