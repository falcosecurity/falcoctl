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
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	isatty "github.com/mattn/go-isatty"
	"github.com/pterm/pterm"
)

// TableHeader is used to print out the correct header for a command.
type TableHeader int

const (
	// ArtifactSearch identifies the header for artifact search.
	ArtifactSearch TableHeader = iota
	// IndexList identifies the header for index list.
	IndexList
	// ArtifactInfo identifies the header for artifact info.
	ArtifactInfo
)

var spinnerCharset = []string{"⠈⠁", "⠈⠑", "⠈⠱", "⠈⡱", "⢀⡱", "⢄⡱", "⢄⡱", "⢆⡱", "⢎⡱", "⢎⡰", "⢎⡠", "⢎⡀", "⢎⠁", "⠎⠁", "⠊⠁"}

// NewProgressBar returns a new progress bar printer.
func NewProgressBar() pterm.ProgressbarPrinter {
	return *pterm.DefaultProgressbar.
		WithTitleStyle(pterm.NewStyle(pterm.FgDefault)).
		WithBarStyle(pterm.NewStyle(pterm.FgDefault)).
		WithBarCharacter("#").
		WithLastCharacter("#").
		WithShowElapsedTime(false).
		WithShowCount(false).
		WithMaxWidth(90).
		WithRemoveWhenDone(true)
}

// Printer used by all commands to output messages.
// If a commands needs a new format for its output add it here.
type Printer struct {
	Logger         *pterm.Logger
	DefaultText    *pterm.BasicTextPrinter
	TablePrinter   *pterm.TablePrinter
	ProgressBar    *pterm.ProgressbarPrinter
	Spinner        *pterm.SpinnerPrinter
	DisableStyling bool
}

// NewPrinter returns a printer ready to be used.
func NewPrinter(logLevel pterm.LogLevel, logFormatter pterm.LogFormatter, writer io.Writer) *Printer {
	var disableStyling bool
	// If we are not in a tty then make sure that the disableStyling variable is set to true since
	// we use it elsewhere to check if we are in a tty or not. We force the disableStyling to true
	// only if it is set to false and we are not in a tty. Otherwise let it as it is, false if the
	// user has not set it (default) otherwise true.
	if (logFormatter != pterm.LogFormatterJSON && !isatty.IsTerminal(os.Stdout.Fd())) || logFormatter == pterm.LogFormatterJSON {
		disableStyling = true
	}

	logger := pterm.DefaultLogger.
		WithLevel(logLevel).WithFormatter(logFormatter).
		WithMaxWidth(150)

	basicText := &pterm.BasicTextPrinter{}

	tablePrinter := pterm.DefaultTable.WithHasHeader().WithSeparator("\t")
	spinner := &pterm.SpinnerPrinter{
		Sequence:            spinnerCharset,
		Style:               pterm.NewStyle(pterm.FgDefault),
		Delay:               time.Millisecond * 100,
		MessageStyle:        pterm.NewStyle(pterm.FgDefault),
		RemoveWhenDone:      true,
		ShowTimer:           true,
		TimerRoundingFactor: time.Second,
		TimerStyle:          &pterm.ThemeDefault.TimerStyle,
	}

	printer := Printer{
		DefaultText:    basicText,
		TablePrinter:   tablePrinter,
		Spinner:        spinner,
		DisableStyling: disableStyling,
		Logger:         logger,
	}

	// We disable styling when the program is not attached to a tty or when requested by the user.
	if disableStyling {
		pterm.DisableStyling()
	}

	return printer.WithWriter(writer)
}

// CheckErr prints a user-friendly error based on the active printer.
func (p *Printer) CheckErr(err error) {
	var handlerFunc func(msg string)
	switch {
	case err == nil:
		return

	// Stop the spinner, if active.
	case p != nil && p.Spinner.IsActive:
		handlerFunc = func(msg string) {
			_ = p.Spinner.Stop()
			p.Logger.Error(msg)
		}
		// Stop the progress bar, if active.
	case p != nil && p.ProgressBar != nil && p.ProgressBar.IsActive:

		handlerFunc = func(msg string) {
			_, _ = p.ProgressBar.Stop()
			p.Logger.Error(msg)
		}

	// If the printer is initialized then print the error through it.
	case p != nil:
		handlerFunc = func(msg string) {
			p.Logger.Error(msg)
		}

	// Otherwise, restore the default behavior.
	// It should never happen.
	default:
		handlerFunc = func(msg string) {
			fmt.Printf("%s (it seems that the printer has not been initialized, that's why you are seeing this message", msg)
		}
	}

	handlerFunc(err.Error())
}

// PrintTable is a helper used to print data in table format.
func (p *Printer) PrintTable(header TableHeader, data [][]string) error {
	var table [][]string

	switch header {
	case ArtifactSearch:
		table = [][]string{{"INDEX", "ARTIFACT", "TYPE", "REGISTRY", "REPOSITORY"}}
	case IndexList:
		table = [][]string{{"NAME", "URL", "ADDED", "UPDATED"}}
	case ArtifactInfo:
		table = [][]string{{"REF", "TAGS"}}
	default:
		return fmt.Errorf("unsupported output table")
	}

	table = append(table, data...)

	return p.TablePrinter.WithData(table).Render()
}

// WithWriter sets the writer for the current printer.
func (p Printer) WithWriter(writer io.Writer) *Printer {
	if writer != nil {
		p.Spinner = p.Spinner.WithWriter(writer)
		p.DefaultText = p.DefaultText.WithWriter(writer)
		p.TablePrinter = p.TablePrinter.WithWriter(writer)
		p.Logger = p.Logger.WithWriter(writer)
	}
	return &p
}

// ExitOnErr aborts the execution in case of errors, and prints the error using the configured printer.
func ExitOnErr(p *Printer, err error) {
	if err != nil {
		p.CheckErr(err)
		os.Exit(1)
	}
}

// FormatTitleAsLoggerInfo returns the msg formatted as been printed by
// the Info logger.
func (p *Printer) FormatTitleAsLoggerInfo(msg string) string {
	buf := &bytes.Buffer{}
	p.Logger.WithWriter(buf).Info(msg)
	return strings.TrimRight(buf.String(), "\n")
}
