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

// main package :)
package main

import (
	"context"
	"os"

	"github.com/falcosecurity/falcoctl/cmd"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

func main() {
	// Set up the root cmd.
	opt := options.NewOptions()
	opt.Initialize(options.WithWriter(os.Stdout))
	rootCmd := cmd.New(context.Background(), opt)

	// Execute the command.
	if err := cmd.Execute(rootCmd, opt.Printer); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
