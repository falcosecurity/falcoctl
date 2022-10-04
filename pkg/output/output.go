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

package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"k8s.io/kubectl/pkg/cmd/util"
)

// TableHeader is used to print out the correct header for a command.
type TableHeader int

const (
	// ArtifactSearch identifies the header for artifact search.
	ArtifactSearch TableHeader = iota
	// IndexList identifies the header for index list.
	IndexList
	// ArtifactInfo identifies the header for artifact info
	ArtifactInfo
)

var spinnerCharset = []string{"⠈⠁", "⠈⠑", "⠈⠱", "⠈⡱", "⢀⡱", "⢄⡱", "⢄⡱", "⢆⡱", "⢎⡱", "⢎⡰", "⢎⡠", "⢎⡀", "⢎⠁", "⠎⠁", "⠊⠁"}

// Printer used by all commands to output messages.
// If a commands needs a new format for its output add it here.
type Printer struct {
	Info    *pterm.PrefixPrinter
	Success *pterm.PrefixPrinter
	Warning *pterm.PrefixPrinter
	Error   *pterm.PrefixPrinter

	DefaultText  *pterm.BasicTextPrinter
	TablePrinter *pterm.TablePrinter

	ProgressBar *pterm.ProgressbarPrinter

	Spinner *pterm.SpinnerPrinter

	verbose bool
}

// NewPrinter returns a printer ready to be used.
func NewPrinter(scope string, verbose bool, writer io.Writer) *Printer {
	generic := &pterm.PrefixPrinter{MessageStyle: pterm.NewStyle(pterm.FgDefault)}
	basicText := &pterm.BasicTextPrinter{}
	progressBar := pterm.DefaultProgressbar.
		WithTitleStyle(pterm.NewStyle(pterm.FgDefault)).
		WithBarStyle(pterm.NewStyle(pterm.FgDefault)).
		WithBarCharacter("#").
		WithLastCharacter("#").
		WithShowElapsedTime(false)
	tablePrinter := pterm.DefaultTable.WithHasHeader().WithSeparator("\t")
	spinner := &pterm.SpinnerPrinter{
		Sequence:            spinnerCharset,
		Style:               pterm.NewStyle(pterm.FgDefault),
		Delay:               time.Millisecond * 100,
		MessageStyle:        pterm.NewStyle(pterm.FgDefault),
		RemoveWhenDone:      false,
		ShowTimer:           true,
		TimerRoundingFactor: time.Second,
		TimerStyle:          &pterm.ThemeDefault.TimerStyle,
	}

	if scope != "" {
		generic = generic.WithScope(pterm.Scope{Text: scope, Style: pterm.NewStyle(pterm.FgGray)})
	}

	if writer != nil {
		generic = generic.WithWriter(writer)
		spinner = spinner.WithWriter(writer)
		basicText = basicText.WithWriter(writer)
		progressBar = progressBar.WithWriter(writer)
		tablePrinter = tablePrinter.WithWriter(writer)
	}

	printer := &Printer{
		verbose: verbose,
		Info: generic.WithPrefix(pterm.Prefix{
			Text:  "INFO",
			Style: pterm.NewStyle(pterm.FgDefault),
		}),

		Success: generic.WithPrefix(pterm.Prefix{
			Text:  "INFO",
			Style: pterm.NewStyle(pterm.FgLightGreen),
		}),

		Warning: generic.WithPrefix(pterm.Prefix{
			Text:  "WARN",
			Style: pterm.NewStyle(pterm.FgYellow),
		}),

		Error: generic.WithPrefix(pterm.Prefix{
			Text:  "ERRO",
			Style: pterm.NewStyle(pterm.FgRed),
		}),

		DefaultText: basicText,

		ProgressBar: progressBar,

		TablePrinter: tablePrinter,

		Spinner: spinner,
	}

	// Populate the printers for the spinner. We use the same one define in the printer.
	printer.Spinner.FailPrinter = printer.Error
	printer.Spinner.WarningPrinter = printer.Warning
	printer.Spinner.SuccessPrinter = printer.Info

	return printer
}

// CheckErr prints a user-friendly error and exits with a non-zero exit code.
// Based on the printer's configuration it will print through it or will use the
// STDERR.
func (p *Printer) CheckErr(err error) {
	switch {
	case err == nil:
		return

	// Print the error through the spinner, if active.
	case p != nil && p.Spinner.IsActive:
		util.BehaviorOnFatal(func(msg string, code int) {
			p.Spinner.Fail(msg)
			os.Exit(code)
		})

	// If the printer is initialized then print the error through it.
	case p != nil:
		util.BehaviorOnFatal(func(msg string, code int) {
			msg = strings.TrimPrefix(msg, "error: ")
			p.Error.Println(strings.TrimRight(msg, "\n"))
			os.Exit(code)
		})

	// Otherwise, restore the default behavior.
	default:
		util.DefaultBehaviorOnFatal()
	}

	// Here we are leveraging a package from kubectl.
	util.CheckErr(err)
}

// Verbosef outputs verbose messages if the verbose flags is set.
func (p *Printer) Verbosef(format string, args ...interface{}) {
	if p.verbose {
		p.Info.Printfln(strings.TrimRight(format, "\n"), args...)
	}
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

	for i := range data {
		table = append(table, data[i])
	}

	return p.TablePrinter.WithData(table).Render()
}

// ExitOnErr aborts the execution in case of errors, without printing any error message.
func ExitOnErr(err error) {
	if err != nil {
		os.Exit(util.DefaultErrorExitCode)
	}
}
