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

package options

import (
	"github.com/gookit/color"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/pterm/pterm"
)

var _ = Describe("LogFormat", func() {
	var (
		logFormatter *LogFormat
	)
	BeforeEach(func() {
		logFormatter = NewLogFormat()
	})

	Context("NewLogFormat Func", func() {
		It("should return a new logFormatter", func() {
			Expect(logFormatter).ShouldNot(BeNil())
			Expect(logFormatter.value).Should(Equal(LogFormatColor))
			Expect(logFormatter.allowed).Should(Equal(logFormats))
		})
	})

	Context("ToPtermFormatter Func", func() {
		var output pterm.LogFormatter

		JustBeforeEach(func() {
			output = logFormatter.ToPtermFormatter()
		})

		Context("Color", func() {
			BeforeEach(func() {
				Expect(logFormatter.Set(LogFormatColor)).ShouldNot(HaveOccurred())
			})

			It("should return the color logFormatter", func() {
				Expect(output).Should(Equal(pterm.LogFormatterColorful))
				Expect(pterm.PrintColor).Should(BeTrue())
				Expect(color.Enable).Should(BeTrue())
			})
		})

		Context("Text", func() {
			BeforeEach(func() {
				Expect(logFormatter.Set(LogFormatText)).ShouldNot(HaveOccurred())
			})

			AfterEach(func() {
				pterm.EnableColor()
			})

			It("should return the text logFormatter", func() {
				Expect(output).Should(Equal(pterm.LogFormatterColorful))
				Expect(pterm.PrintColor).Should(BeFalse())
				Expect(color.Enable).Should(BeFalse())
			})
		})

		Context("JSON", func() {
			BeforeEach(func() {
				Expect(logFormatter.Set(LogFormatJSON)).ShouldNot(HaveOccurred())
			})

			It("should return the json logFormatter", func() {
				Expect(output).Should(Equal(pterm.LogFormatterJSON))
				Expect(pterm.PrintColor).Should(BeTrue())
				Expect(color.Enable).Should(BeTrue())
			})
		})
	})
})
