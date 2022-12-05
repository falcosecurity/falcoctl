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

package pull

import (
	"context"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

var longPull = `Pull Falco "rulefile" or "plugin" OCI artifacts from remote registry

Example - Pull artifact "myplugin" of type "plugin" for the platform where falcoctl is running (default) in the current working directory (default):
	falcoctl registry pull localhost:5000/myplugin:latest --type plugin

Example - Pull artifact "myplugin" of type "plugin" for platform "linux/aarch64" in the current working directory (default):
	falcoctl registry pull localhost:5000/myplugin:latest --type plugin --platform linux/aarch64

Example - Pull artifact "myplugin" of type "plugin" for platform "linux/aarch64" in "myDir" directory:
	falcoctl registry pull localhost:5000/myplugin:latest --type plugin --platform linux/aarch64 --dest-dir=./myDir

Example - Pull artifact "myrulesfile" of type "rulesfile":
	falcoctl registry pull localhost:5000/myrulesfile:latest --type rulesfile
`

type pullOptions struct {
	*options.CommonOptions
	*options.ArtifactOptions
	destDir string
}

func (o *pullOptions) Validate() error {
	return o.ArtifactOptions.Validate()
}

// NewPullCmd returns the pull command.
func NewPullCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := pullOptions{
		CommonOptions:   opt,
		ArtifactOptions: &options.ArtifactOptions{},
	}

	cmd := &cobra.Command{
		Use:                   "pull hostname/repo[:tag|@digest] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Pull a Falco OCI artifact from remote registry",
		Long:                  longPull,
		Args:                  cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate())
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunPull(ctx, args))
		},
	}
	o.CommonOptions.AddFlags(cmd.Flags())
	o.Printer.CheckErr(o.ArtifactOptions.AddFlags(cmd))
	cmd.Flags().StringVarP(&o.destDir, "dest-dir", "o", "", "destination dir where to save the artifacts(default: current directory)")
	return cmd
}

// RunPull executes the business logic for the pull command.
func (o *pullOptions) RunPull(ctx context.Context, args []string) error {
	ref := args[0]
	o.Printer.Info.Printfln("Preparing to pull artifact %q", args[0])

	registry, err := utils.GetRegistryFromRef(ref)
	if err != nil {
		return err
	}

	puller, err := utils.PullerForRegistry(ctx, registry, true, true, o.Printer)
	if err != nil {
		return fmt.Errorf("an error occurred while creating the puller for registry %s: %w", registry, err)
	}

	if o.destDir == "" {
		o.Printer.Info.Printfln("Pulling artifact in the current directory")
	} else {
		o.Printer.Info.Printfln("Pulling artifact in %q directory", o.destDir)
	}

	os, arch := runtime.GOOS, runtime.GOARCH
	if len(o.ArtifactOptions.Platforms) > 0 {
		os, arch = o.OSArch(0)
	}

	res, err := puller.Pull(ctx, ref, o.destDir, os, arch)
	if err != nil {
		return err
	}

	o.Printer.Success.Printfln("Artifact of type %q pulled. Digest: %q", res.Type, res.Digest)

	return nil
}
