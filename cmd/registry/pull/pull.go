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

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/login"
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	longPull = `Pull Falco "rulesfile" or "plugin" OCI artifacts from remote registry.

Artifact references are passed as arguments. 

A reference is either a simple name or a fully qualified reference ("<registry>/<repository>"), 
optionally followed by ":<tag>" (":latest" is assumed by default when no tag is given).

When providing just the name of the artifact, the command will search for the artifacts in 
the configured index files, and if found, it will use the registry and repository specified 
in the indexes.

Example - Pull artifact "myplugin" of type "plugin" for the platform where falcoctl is running (default) in the current working directory (default):
	falcoctl registry pull localhost:5000/myplugin:latest --type plugin

Example - Pull artifact "myplugin" of type "plugin" for platform "linux/aarch64" in the current working directory (default):
	falcoctl registry pull localhost:5000/myplugin:latest --type plugin --platform linux/aarch64

Example - Pull artifact "myplugin" of type "plugin" for platform "linux/aarch64" in "myDir" directory:
	falcoctl registry pull localhost:5000/myplugin:latest --type plugin --platform linux/aarch64 --dest-dir=./myDir

Example - Pull artifact "myrulesfile" of type "rulesfile":
	falcoctl registry pull localhost:5000/myrulesfile:latest --type rulesfile
`
)

type pullOptions struct {
	*options.CommonOptions
	*options.ArtifactOptions
	*options.RegistryOptions
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
		RegistryOptions: &options.RegistryOptions{},
	}

	cmd := &cobra.Command{
		Use:                   "pull hostname/repo[:tag|@digest] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Pull a Falco OCI artifact from remote registry",
		Long:                  longPull,
		Args:                  cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate())

			// Perform authentications using basic auth.
			basicAuths, err := config.BasicAuths()
			opt.Printer.CheckErr(err)
			opt.Printer.CheckErr(login.PerformBasicAuthsLogin(ctx, basicAuths))

			// Perform authentications using oauth auth.
			oauthAuths, err := config.OauthAuths()
			opt.Printer.CheckErr(err)
			opt.Printer.CheckErr(login.PerformOauthAuths(ctx, o.CommonOptions, oauthAuths))
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunPull(ctx, args))
		},
	}

	o.RegistryOptions.AddFlags(cmd)
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

	puller, err := utils.PullerForRegistry(ctx, registry, o.PlainHTTP, o.Printer)
	if err != nil {
		return fmt.Errorf("an error occurred while creating the puller for registry %s: %w", registry, err)
	}

	if o.destDir == "" {
		o.Printer.Info.Printfln("Pulling artifact in the current directory")
	} else {
		o.Printer.Info.Printfln("Pulling artifact in %q directory", o.destDir)
	}

	os, arch := runtime.GOOS, utils.PlatformArchitecture(runtime.GOARCH)
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
