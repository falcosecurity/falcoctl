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

package manifest

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	ociutils "github.com/falcosecurity/falcoctl/pkg/oci/utils"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type artifactManifestOptions struct {
	*options.Common
	*options.Registry
	platform string
}

// NewArtifactManifestCmd returns the artifact manifest command.
func NewArtifactManifestCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := artifactManifestOptions{
		Common:   opt,
		Registry: &options.Registry{},
	}

	cmd := &cobra.Command{
		Use:   "manifest [ref] [flags]",
		Short: "Get the manifest layer of an artifact",
		Long:  "Get the manifest layer of an artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunArtifactManifest(ctx, args)
		},
	}

	o.Registry.AddFlags(cmd)
	cmd.Flags().StringVar(&o.platform, "platform", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		"os and architecture of the artifact in OS/ARCH format")

	return cmd
}

func (o *artifactManifestOptions) RunArtifactManifest(ctx context.Context, args []string) error {
	var (
		puller   *ocipuller.Puller
		ref      string
		manifest []byte
		err      error
	)

	// Create puller with auto login enabled.
	if puller, err = ociutils.Puller(o.PlainHTTP, o.Printer); err != nil {
		return err
	}

	// Resolve the artifact reference.
	if ref, err = o.IndexCache.ResolveReference(args[0]); err != nil {
		return err
	}

	// TODO: implement two new flags (platforms, platform) based on the oci platform struct.
	// Split the platform.
	tokens := strings.Split(o.platform, "/")
	if len(tokens) != 2 {
		return fmt.Errorf("invalid platform format: %s", o.platform)
	}

	if manifest, err = puller.RawManifest(ctx, ref, tokens[0], tokens[1]); err != nil {
		return err
	}

	o.Printer.DefaultText.Println(string(manifest))

	return nil
}
