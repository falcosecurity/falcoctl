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

package pull

import (
	"context"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/utils"
	ociutils "github.com/falcosecurity/falcoctl/pkg/oci/utils"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	longPull = `Pull Falco "rulesfile" or "plugin" OCI artifacts from remote registry.

Artifact references are passed as arguments.

A reference is a fully qualified reference ("<registry>/<repository>"),
optionally followed by ":<tag>" (":latest" is assumed by default when no tag is given).

Example - Pull artifact "myplugin" for the platform where falcoctl is running (default) in the current working directory (default):
	falcoctl registry pull localhost:5000/myplugin:latest

Example - Pull artifact "myplugin" for platform "linux/arm64" in the current working directory (default):
	falcoctl registry pull localhost:5000/myplugin:latest --platform linux/arm64

Example - Pull artifact "myplugin" for platform "linux/arm64" in "myDir" directory:
	falcoctl registry pull localhost:5000/myplugin:latest --platform linux/arm64 --dest-dir=./myDir

Example - Pull artifact "myrulesfile":
	falcoctl registry pull localhost:5000/myrulesfile:latest
`
)

type pullOptions struct {
	*options.Common
	*options.Artifact
	*options.Registry
	destDir string
}

func (o *pullOptions) Validate() error {
	return o.Artifact.Validate()
}

// NewPullCmd returns the pull command.
func NewPullCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := pullOptions{
		Common:   opt,
		Artifact: &options.Artifact{},
		Registry: &options.Registry{},
	}

	cmd := &cobra.Command{
		Use:                   "pull hostname/repo[:tag|@digest] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Pull a Falco OCI artifact from remote registry",
		Long:                  longPull,
		Args:                  cobra.ExactArgs(1),
		SilenceErrors:         true,
		SilenceUsage:          true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := o.Validate(); err != nil {
				return err
			}

			ref := args[0]

			_, err := utils.GetRegistryFromRef(ref)
			if err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunPull(ctx, args)
		},
	}

	o.Registry.AddFlags(cmd)
	output.ExitOnErr(o.Printer, o.Artifact.AddFlags(cmd))
	cmd.Flags().StringVarP(&o.destDir, "dest-dir", "o", "", "destination dir where to save the artifacts(default: current directory)")
	return cmd
}

// RunPull executes the business logic for the pull command.
func (o *pullOptions) RunPull(ctx context.Context, args []string) error {
	ref := args[0]

	registry, err := utils.GetRegistryFromRef(ref)
	if err != nil {
		return err
	}

	puller, err := ociutils.Puller(o.PlainHTTP, o.Printer)
	if err != nil {
		return fmt.Errorf("an error occurred while creating the puller for registry %s: %w", registry, err)
	}

	err = ociutils.CheckConnectionForRegistry(ctx, puller.Client, o.PlainHTTP, registry)
	if err != nil {
		return err
	}

	o.Printer.Info.Printfln("Preparing to pull artifact %q", args[0])

	if o.destDir == "" {
		o.Printer.Info.Printfln("Pulling artifact in the current directory")
	} else {
		o.Printer.Info.Printfln("Pulling artifact in %q directory", o.destDir)
	}

	os, arch := runtime.GOOS, runtime.GOARCH
	if len(o.Artifact.Platforms) > 0 {
		os, arch = o.OSArch(0)
	}

	res, err := puller.Pull(ctx, ref, o.destDir, os, arch)
	if err != nil {
		return err
	}

	o.Printer.Success.Printfln("Artifact of type %q pulled. Digest: %q", res.Type, res.Digest)

	return nil
}
