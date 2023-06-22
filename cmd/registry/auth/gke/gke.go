// Copyright 2023 The Falco Authors
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

package gke

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/login/gke"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	longGke = `Register a registry to use Workload Identity to connect to it.

Example 
	falcoctl registry gke europe-docker.pkg.dev
`
)

// RegistryGkeOptions contains the options for the registry gke command.
type RegistryGkeOptions struct {
	*options.CommonOptions
	registry string
}

// NewGkeCmd returns the gke command.
func NewGkeCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := RegistryGkeOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "gke [REGISTRY]",
		DisableFlagsInUseLine: true,
		Short:                 "Register an OCI registry to log in using Workload identity",
		Long:                  longGke,
		Args:                  cobra.ExactArgs(1),
		SilenceErrors:         true,
		SilenceUsage:          true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunGke(ctx, args)
		},
	}

	return cmd
}

// RunGke executes the business logic for the gke command.
func (o *RegistryGkeOptions) RunGke(ctx context.Context, args []string) error {
	var err error
	reg := args[0]
	if err = gke.Login(ctx, reg); err != nil {
		return err
	}
	o.Printer.Success.Printfln("GKE source correctly set for %q", o.registry)

	o.Printer.Verbosef("Adding new gke entry to configuration file %q", o.ConfigFile)
	if err = config.AddGke([]config.GkeAuth{{
		Registry: reg,
	}}, o.ConfigFile); err != nil {
		return fmt.Errorf("index entry %q: %w", reg, err)
	}

	o.Printer.Success.Printfln("Gke auth entry for %q successfully added", reg)

	return nil
}
