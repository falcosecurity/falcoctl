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

package gcp

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/login/gcp"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	longGcp = `Register an Artifact Registry to use GCP Application Default credentials to connect to it.

In particular, it can use Workload Identity or GCE metadata server to authenticate.

Example 
	falcoctl registry auth gcp europe-docker.pkg.dev
`
)

// RegistryGcpOptions contains the options for the registry gcp command.
type RegistryGcpOptions struct {
	*options.Common
}

// NewGcpCmd returns the gcp command.
func NewGcpCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := RegistryGcpOptions{
		Common: opt,
	}

	cmd := &cobra.Command{
		Use:                   "gcp [REGISTRY]",
		DisableFlagsInUseLine: true,
		Short:                 "Register an Artifact Registry to log in using GCP Application Default credentials",
		Long:                  longGcp,
		Args:                  cobra.ExactArgs(1),
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunGcp(ctx, args)
		},
	}

	return cmd
}

// RunGcp executes the business logic for the gcp command.
func (o *RegistryGcpOptions) RunGcp(ctx context.Context, args []string) error {
	var err error
	reg := args[0]
	if err = gcp.Login(ctx, reg); err != nil {
		return err
	}
	o.Printer.Success.Printfln("GCP authentication successful for %q", reg)

	o.Printer.Verbosef("Adding new gcp entry to configuration file %q", o.ConfigFile)
	if err = config.AddGcp([]config.GcpAuth{{
		Registry: reg,
	}}, o.ConfigFile); err != nil {
		return fmt.Errorf("index entry %q: %w", reg, err)
	}

	o.Printer.Success.Printfln("GCP authentication entry for %q successfully added in configuration file", reg)

	return nil
}
