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
	"errors"
	"fmt"
	"io"

	"github.com/gookit/color"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/pterm/pterm"
)

var _ = Describe("NewPrinter func", func() {
	var (
		printer      *Printer
		logFormatter pterm.LogFormatter
		logLevel     pterm.LogLevel
		writer       io.Writer
	)

	JustBeforeEach(func() {
		printer = NewPrinter(logLevel, logFormatter, writer)
	})

	JustAfterEach(func() {
		printer = nil
		logFormatter = 1000
		logLevel = 1000
		writer = nil
	})

	Context("with writer", func() {
		BeforeEach(func() {
			writer = &bytes.Buffer{}
		})

		It("should correctly set the writer for each printer object", func() {
			Expect(printer.Logger.Writer).Should(Equal(writer))
			Expect(printer.Spinner.Writer).Should(Equal(writer))
			Expect(printer.DefaultText.Writer).Should(Equal(writer))
			Expect(printer.TablePrinter.Writer).Should(Equal(writer))
		})
	})

	Context("with log-level", func() {
		Describe("info", func() {
			BeforeEach(func() {
				logLevel = pterm.LogLevelInfo
			})
			It("should correctly set the log level to info", func() {
				Expect(printer.Logger.Level).Should(Equal(pterm.LogLevelInfo))
			})
		})

		Describe("warn", func() {
			BeforeEach(func() {
				logLevel = pterm.LogLevelWarn
			})
			It("should correctly set the log level to warn", func() {
				Expect(printer.Logger.Level).Should(Equal(pterm.LogLevelWarn))
			})
		})

		Describe("debug", func() {
			BeforeEach(func() {
				logLevel = pterm.LogLevelDebug
			})
			It("should correctly set the log level to debug", func() {
				Expect(printer.Logger.Level).Should(Equal(pterm.LogLevelDebug))
			})
		})

		Describe("error", func() {
			BeforeEach(func() {
				logLevel = pterm.LogLevelError
			})
			It("should correctly set the log level to error", func() {
				Expect(printer.Logger.Level).Should(Equal(pterm.LogLevelError))
			})
		})
	})

	Context("with log-formatter", func() {
		Describe("colorful", func() {
			BeforeEach(func() {
				logFormatter = pterm.LogFormatterColorful
			})
			It("should correctly set the log formatter to colorful", func() {
				Expect(printer.Logger.Formatter).Should(Equal(pterm.LogFormatterColorful))
			})
		})

		Describe("json", func() {
			BeforeEach(func() {
				logFormatter = pterm.LogFormatterJSON
			})

			It("should correctly set the log level to json", func() {
				Expect(printer.Logger.Formatter).Should(Equal(pterm.LogFormatterJSON))
			})

			It("should correctly disable styling at pterm package level", func() {
				Expect(pterm.RawOutput).Should(BeTrue())
			})

			It("should correctly disable color at pterm package level", func() {
				Expect(pterm.PrintColor).Should(BeFalse())
			})

			It("should correctly disable color at color package level", func() {
				Expect(color.Enable).Should(BeFalse())
			})
		})
	})
})

var _ = Describe("CheckErr func", func() {
	var (
		buf     *gbytes.Buffer
		printer *Printer
		err     error
	)

	JustBeforeEach(func() {
		printer.CheckErr(err)
	})

	JustAfterEach(func() {
		printer = nil
		Expect(buf.Clear()).ShouldNot(HaveOccurred())
		err = nil
	})

	Context("printer is nil", func() {
		BeforeEach(func() {
			buf = gbytes.NewBuffer()
			// Set printer to nil.
			printer = nil
			err = errors.New("printer is set to nil")
		})

		It("should print using fmt", func() {
			Expect(buf).ShouldNot(gbytes.Say(
				fmt.Sprintf("%s (it seems that the printer has not been initialized, that's why you are seeing this message)", err.Error())))
		})
	})

	Context("only printer is active and defined", func() {
		BeforeEach(func() {
			buf = gbytes.NewBuffer()
			// Set printer to nil.
			printer = NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterColorful, buf)
			// Make sure that no other printers are active.
			Expect(printer.ProgressBar).Should(BeNil())
			Expect(printer.Spinner.IsActive).Should(BeFalse())
			err = errors.New("only printers without effects")
		})

		It("should print using fmt", func() {
			Expect(buf).Should(gbytes.Say(err.Error()))
		})
	})

	Context("error is nil", func() {
		BeforeEach(func() {
			buf = gbytes.NewBuffer()
			// Set printer to nil.
			printer = NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterColorful, buf)
			// Make sure that no other printers are active.
			Expect(printer.ProgressBar).Should(BeNil())
			Expect(printer.Spinner.IsActive).Should(BeFalse())
			err = nil
		})

		It("should print nothing", func() {
			Expect(len(buf.Contents())).Should(BeZero())
		})
	})

	Context("spinner is active", func() {
		BeforeEach(func() {
			buf = gbytes.NewBuffer()
			printer = NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterColorful, buf)
			printer.Spinner, _ = printer.Spinner.Start()
			// Check that the spinner is active.
			Expect(printer.Spinner.IsActive).Should(BeTrue())
			err = errors.New("spinner is active")
		})

		It("should print using logger", func() {
			Expect(buf).Should(gbytes.Say(err.Error()))
		})

		It("should stop the spinner", func() {
			Expect(printer.Spinner.IsActive).Should(BeFalse())
		})
	})

	Context("spinner progress bar is active", func() {
		BeforeEach(func() {
			buf = gbytes.NewBuffer()
			printer = NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterColorful, buf)
			printer.ProgressBar, _ = NewProgressBar().Start()
			// Check that the progress bar is active.
			Expect(printer.ProgressBar.IsActive).Should(BeTrue())
			err = errors.New("progress bar is active")
		})

		It("should print using logger", func() {
			Expect(buf).Should(gbytes.Say(err.Error()))
		})

		It("should stop the progress bar", func() {
			Expect(printer.ProgressBar.IsActive).Should(BeFalse())
		})
	})

})

var _ = Describe("PrintTable func", func() {
	var (
		buf     *gbytes.Buffer
		printer *Printer
		header  TableHeader
		err     error
	)

	JustBeforeEach(func() {
		printer = NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterColorful, buf)
		err = printer.PrintTable(header, nil)
	})

	JustAfterEach(func() {
		printer = nil
		Expect(buf.Clear()).ShouldNot(HaveOccurred())
		header = 1000
	})

	Context("artifact search header", func() {
		BeforeEach(func() {
			buf = gbytes.NewBuffer()
			header = ArtifactSearch
		})

		It("should print header", func() {
			header := []string{"INDEX", "ARTIFACT", "TYPE", "REGISTRY", "REPOSITORY"}
			for _, col := range header {
				Expect(buf).Should(gbytes.Say(col))
			}
		})
	})

	Context("index list header", func() {
		BeforeEach(func() {
			buf = gbytes.NewBuffer()
			header = IndexList
		})

		It("should print header", func() {
			header := []string{"NAME", "URL", "ADDED", "UPDATED"}
			for _, col := range header {
				Expect(buf).Should(gbytes.Say(col))
			}
		})
	})

	Context("index list header", func() {
		BeforeEach(func() {
			buf = gbytes.NewBuffer()
			header = ArtifactInfo
		})

		It("should print header", func() {
			header := []string{"REF", "TAGS"}
			for _, col := range header {
				Expect(buf).Should(gbytes.Say(col))
			}
		})
	})

	Context("header is not defined", func() {
		BeforeEach(func() {
			buf = gbytes.NewBuffer()
			header = 1000
		})

		It("should error", func() {
			Expect(err).ShouldNot(BeNil())
		})
	})

})

var _ = Describe("FormatTitleAsLoggerInfo func", func() {
	var (
		printer      *Printer
		msg          string
		formattedMsg string
	)

	JustBeforeEach(func() {
		printer = NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterColorful, nil)
		formattedMsg = printer.FormatTitleAsLoggerInfo(msg)
	})

	JustAfterEach(func() {
		printer = nil
	})

	Context("message without trailing new line", func() {
		BeforeEach(func() {
			msg = "Testing message without new line"
		})

		It("should format according to the INFO logger", func() {
			output := fmt.Sprintf("INFO  %s", msg)
			Expect(formattedMsg).Should(ContainSubstring(output))
		})
	})

	Context("message with trailing new line", func() {
		BeforeEach(func() {
			msg = "Testing message with new line"
		})

		It("should format according to the INFO logger and remove newline", func() {
			output := fmt.Sprintf("INFO  %s", msg)
			Expect(formattedMsg).Should(ContainSubstring(output))
			Expect(formattedMsg).ShouldNot(ContainSubstring("\n"))
		})
	})

})
