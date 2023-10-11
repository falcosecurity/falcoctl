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

package output

import (
	"bytes"
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Output", func() {
	var (
		printer *Printer
		scope   string
		verbose bool
		writer  io.Writer
	)

	JustBeforeEach(func() {
		printer = NewPrinter(scope, false, verbose, writer)
	})

	JustAfterEach(func() {
		printer = nil
		scope = ""
		verbose = false
		writer = nil
	})

	Context("a new printer is created", func() {
		Context("with scope", func() {
			BeforeEach(func() {
				scope = "CustomScope"
			})

			It("should correctly set the scope for each printer object", func() {
				Expect(printer.Error.Scope.Text).Should(Equal(scope))
				Expect(printer.Info.Scope.Text).Should(Equal(scope))
				Expect(printer.Warning.Scope.Text).Should(Equal(scope))
			})
		})

		Context("with writer", func() {
			BeforeEach(func() {
				writer = &bytes.Buffer{}
			})

			It("should correctly set the writer for each printer object", func() {
				Expect(printer.Error.Writer).Should(Equal(writer))
				Expect(printer.Info.Writer).Should(Equal(writer))
				Expect(printer.Warning.Writer).Should(Equal(writer))
				Expect(printer.DefaultText.Writer).Should(Equal(writer))
			})
		})

		Context("with verbose", func() {
			BeforeEach(func() {
				verbose = true
			})
			It("should correctly set the verbose variable to true", func() {
				Expect(printer.verbose).Should(BeTrue())
			})
		})
	})

	Context("testing output using the verbose function", func() {
		var (
			msg          = "Testing verbose mode"
			customWriter *bytes.Buffer
		)

		BeforeEach(func() {
			// set the output writer.
			customWriter = &bytes.Buffer{}
			writer = customWriter
		})

		JustBeforeEach(func() {
			// call the output function
			printer.Verbosef("%s", msg)
		})

		Context("verbose mode is disabled", func() {
			It("should not output the message", func() {
				Expect(customWriter.String()).Should(BeEmpty())
			})
		})

		Context("verbose mode is enabled", func() {
			BeforeEach(func() {
				verbose = true
			})

			It("should output the message", func() {
				Expect(customWriter.String()).Should(ContainSubstring(msg))
			})
		})
	})
})
