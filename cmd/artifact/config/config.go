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

package config

import (
	"context"

	"github.com/spf13/cobra"

	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	ociutils "github.com/falcosecurity/falcoctl/pkg/oci/utils"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type artifactConfigOptions struct {
	*options.Common
	*options.Registry
}

// NewArtifactConfigCmd returns the artifact config command.
func NewArtifactConfigCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := artifactConfigOptions{
		Common:   opt,
		Registry: &options.Registry{},
	}

	cmd := &cobra.Command{
		Use:   "config [ref] [flags]",
		Short: "Get the config layer of an artifact",
		Long:  "Get the config layer of an artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunArtifactConfig(ctx, args)
		},
	}

	o.Registry.AddFlags(cmd)

	return cmd
}

func (o *artifactConfigOptions) RunArtifactConfig(ctx context.Context, args []string) error {
	var (
		puller *ocipuller.Puller
		ref    string
		config []byte
		err    error
	)

	// Create puller with auto login enabled.
	if puller, err = ociutils.Puller(o.PlainHTTP, o.Printer); err != nil {
		return err
	}

	// Resolve the artifact reference.
	if ref, err = o.IndexCache.ResolveReference(args[0]); err != nil {
		return err
	}

	if config, err = puller.PullConfigLayer(ctx, ref); err != nil {
		return err
	}

	o.Printer.DefaultText.Println(string(config))

	return nil
}
