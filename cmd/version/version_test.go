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

package version

import (
	"encoding/json"
	"fmt"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"gopkg.in/yaml.v3"

	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

var _ = Describe("Version", func() {
	var (
		opt       *options
		outputFmt string
		version   = &version{
			SemVersion: "0.0.0",
			GitCommit:  "d502313",
			BuildDate:  "2022-08-18_06:57:24",
			GoVersion:  "go1.19",
			Compiler:   "gc",
			Platform:   "linux/test",
		}
		writer *gbytes.Buffer
	)

	JustBeforeEach(func() {
		writer = gbytes.NewBuffer()
		cfg := commonoptions.NewOptions()
		cfg.Initialize(commonoptions.WithWriter(writer))
		opt = &options{
			Common: cfg,
			Output: outputFmt,
		}
	})

	JustAfterEach(func() {
		opt = nil
		outputFmt = ""
	})

	Context("testing methods based on output flag", func() {
		When("output is not set", func() {
			BeforeEach(func() {
				outputFmt = ""
			})

			Context("validate method", func() {
				It("should not error", func() {
					Expect(opt.validate()).Error().ShouldNot(HaveOccurred())
				})
			})

			Context("run method", func() {
				It("should print only the semVersion", func() {
					Expect(opt.Run(version)).Error().ShouldNot(HaveOccurred())
					Expect(writer).Should(gbytes.Say(version.SemVersion))
				})
			})
		})

		When("output is set to 'yaml'", func() {
			var (
				outputYaml string
			)
			BeforeEach(func() {
				outputFmt = "yaml"
			})

			Context("validate method", func() {
				It("should not error", func() {
					Expect(opt.validate()).Error().ShouldNot(HaveOccurred())
				})
			})

			Context("run method", func() {
				BeforeEach(func() {
					marshaled, err := yaml.Marshal(version)
					Expect(err).ShouldNot(HaveOccurred())
					outputYaml = string(marshaled)
				})

				It("should print the version in yaml", func() {
					Expect(opt.Run(version)).Error().ShouldNot(HaveOccurred())
					Expect(writer).Should(gbytes.Say("Client Version:"))
					Expect(writer).Should(gbytes.Say(outputYaml))
				})
			})
		})

		When("output is set to 'json'", func() {
			var (
				outputJSON string
			)
			BeforeEach(func() {
				outputFmt = "json"
			})

			Context("validate method", func() {
				It("should not error", func() {
					Expect(opt.validate()).Error().ShouldNot(HaveOccurred())
				})
			})

			Context("run method", func() {
				BeforeEach(func() {
					marshaled, err := json.MarshalIndent(version, "", "   ")
					Expect(err).ShouldNot(HaveOccurred())
					outputJSON = string(marshaled)
				})

				It("should print the version in yaml", func() {
					Expect(opt.Run(version)).Error().ShouldNot(HaveOccurred())
					Expect(writer).Should(gbytes.Say("Client Version:"))
					Expect(writer).Should(gbytes.Say(outputJSON))
				})
			})
		})

		When("output is set to invalid value", func() {
			BeforeEach(func() {
				outputFmt = "not a valid values"
			})

			Context("validate method", func() {
				It("should error", func() {
					Expect(opt.validate()).Error().Should(Equal(errOutputFlag))
				})
			})

			Context("run method", func() {
				It("should print the error message", func() {
					Expect(opt.Run(version)).Error().Should(HaveOccurred())
					Expect(writer).Should(gbytes.Say("options of the version command were not validated"))
				})
			})
		})
	})

	Context("testing newVersion function", func() {
		It("should return the expected version struct", func() {
			v := newVersion()
			Expect(v.Compiler).Should(Equal(runtime.Compiler))
			Expect(v.SemVersion).Should(Equal(semVersion))
			Expect(v.GitCommit).Should(Equal(gitCommit))
			Expect(v.BuildDate).Should(Equal(buildDate))
			Expect(v.GoVersion).Should(Equal(runtime.Version()))
			Expect(v.Platform).Should(Equal(fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)))
		})
	})

})
