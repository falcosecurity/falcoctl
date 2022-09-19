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

package cmd

import (
	"context"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"

	"github.com/falcosecurity/falcoctl/cmd/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
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

func newPullProgressTracker(printer *output.Printer) ocipuller.ProgressTracker {
	return func(target oras.Target) oras.Target {
		return output.NewProgressTracker(printer, target, "Pulling")
	}
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
	o.Printer.Info.Printfln("Preparing to pull artifact %q of type %q", args[0], o.ArtifactType)

	registry, err := utils.GetRegistryFromRef(ref)
	if err != nil {
		return err
	}

	credentialStore, err := authn.NewStore([]string{}...)
	if err != nil {
		return err
	}

	o.Printer.Verbosef("Retrieving credentials from local store")
	cred, err := credentialStore.Credential(ctx, registry)
	if err != nil {
		return err
	}
	client := authn.NewClient(cred)

	puller := ocipuller.NewPuller(client, newPullProgressTracker(o.Printer))
	if o.destDir == "" {
		o.Printer.Info.Printfln("Pulling artifact in the current directory")
	} else {
		o.Printer.Info.Printfln("Pulling artifact in %q directory", o.destDir)
	}

	res, err := puller.Pull(ctx, o.ArtifactType, ref, o.destDir, o.GetOS(), o.GetArch())
	if err != nil {
		return err
	}

	o.Printer.Success.Printfln("Artifact pulled. Digest: %q", res.Digest)

	return nil
}
