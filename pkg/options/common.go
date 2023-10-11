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
	"io"

	"github.com/spf13/pflag"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/pkg/index/cache"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

// Common provides the common flags, options, and printers for all the
// commands. All the fields provided by the Common will be initialized before
// the commands are executed through the Initialize func.
type Common struct {
	// Printer used by all commands to output messages.
	Printer *output.Printer
	// printerScope contains the data of the optional scope of a prefix.
	// It used to add a prefix to the output of a printer.
	printerScope string
	// writer is used to write the output of the printer.
	writer io.Writer
	// Used to store the verbose flag, and then passed to the printer.
	verbose bool
	// Disable the styling if set to true.
	disableStyling bool
	// Config file. It must not be possible to be reinitialized by subcommands,
	// using the Initialize function. It will be attached as global flags.
	ConfigFile string
	// IndexCache caches the entries for the configured indexes.
	IndexCache *cache.Cache
}

// NewOptions returns a new Common struct.
func NewOptions() *Common {
	return &Common{}
}

// Configs type of the configs accepted by the Initialize function.
type Configs func(options *Common)

// WithPrinterScope sets the scope for the printer.
func WithPrinterScope(scope string) Configs {
	return func(options *Common) {
		options.printerScope = scope
	}
}

// WithWriter sets the writer for the printer.
func WithWriter(writer io.Writer) Configs {
	return func(options *Common) {
		options.writer = writer
	}
}

// WithIndexCache sets the index cache.
func WithIndexCache(c *cache.Cache) Configs {
	return func(options *Common) {
		options.IndexCache = c
	}
}

// Initialize initializes the options based on the configs. Subsequent calls will overwrite the
// previous configurations based on the new configs passed to the functions.
func (o *Common) Initialize(cfgs ...Configs) {
	for _, cfg := range cfgs {
		cfg(o)
	}

	// create the printer. The value of verbose is a flag value.
	o.Printer = output.NewPrinter(o.printerScope, o.disableStyling, o.verbose, o.writer)
}

// IsVerbose used to check if the verbose flag is set or not.
func (o *Common) IsVerbose() bool {
	return o.verbose
}

// AddFlags registers the common flags.
func (o *Common) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(&o.verbose, "verbose", "v", false, "Enable verbose logs (default false)")
	flags.BoolVar(&o.disableStyling, "disable-styling", false, "Disable output styling such as spinners, progress bars and colors. "+
		"Styling is automatically disabled if not attacched to a tty (default false)")
	// Add global config
	flags.StringVar(&o.ConfigFile, "config", config.ConfigPath, "config file to be used for falcoctl")
}
