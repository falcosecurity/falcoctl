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

package tls

import (
	"fmt"
	"os"
)

// Options represents the `install tls` command o.
type Options struct {
	Country string
	Org     string
	Name    string
	Path    string
	Days    int
	RSABits int
	DNSSANs []string
	IPSANs  []string
}

// Run executes the business logic of the `install tls` command.
func (o *Options) Run() error {
	// If the output path is not given then get the current working directory.
	if o.Path == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("an error occurred while getting working directory: %w", err)
		}
		o.Path = cwd
	}

	generator := GRPCTLSGenerator(o.Country, o.Org, o.Name, o.Days, o.RSABits, o.DNSSANs, o.IPSANs)
	err := generator.Generate()
	if err != nil {
		return err
	}
	err = generator.FlushToDisk(o.Path)
	if err != nil {
		return err
	}

	return nil
}
