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

// main package :)
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/falcosecurity/falcoctl/cmd"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

func main() {
	// Set up the root cmd.
	opt := options.NewOptions()
	opt.Initialize(options.WithWriter(os.Stdout))

	// Register signal handler
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	// If the ctx is marked as done then we reset the signals.
	go func() {
		<-ctx.Done()
		// Stop all the printers if any is active
		if opt.Printer != nil && opt.Printer.ProgressBar != nil && opt.Printer.ProgressBar.IsActive {
			_, _ = opt.Printer.ProgressBar.Stop()
		}
		if opt.Printer != nil && opt.Printer.Spinner != nil && opt.Printer.Spinner.IsActive {
			_ = opt.Printer.Spinner.Stop()
		}
		opt.Printer.Logger.Info("Received signal, terminating...")
		stop()
	}()

	// Create root command
	rootCmd := cmd.New(ctx, opt)

	// Execute the command.
	if err := cmd.Execute(rootCmd, opt); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
