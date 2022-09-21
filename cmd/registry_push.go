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
	"fmt"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2"

	"github.com/falcosecurity/falcoctl/cmd/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

var longPush = `Push Falco "rulefile" or "plugin" OCI artifacts to remote registry

Example - Push artifact "myplugin.tar.gz" of type "plugin" for the platform where falcoctl is running (default):
	falcoctl registry push myplugin.tar.gz localhost:5000/myplugin:latest --type plugin

Example - Push artifact "myplugin.tar.gz" of type "plugin" for platform "linux/aarch64":
	falcoctl registry push myplugin.tar.gz localhost:5000/myplugin:latest --type plugin --platform linux/aarch64

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile":
	falcoctl registry push myrulesfile.tar.gz localhost:5000/myrulesfile:latest --type rulesfile

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with a dependency "myplugin:1.2.3":
	falcoctl registry push myrulesfile.tar.gz localhost:5000/myrulesfile:latest --type rulesfile --depends-on myplugin:1.2.3

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with a dependency "myplugin:1.2.3" and an alternative "otherplugin:3.2.1":
	falcoctl registry push myrulesfile.tar.gz localhost:5000/myrulesfile:latest --type rulesfile --depends-on "myplugin:1.2.3|otherplugin:3.2.1"

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with multiple dependencies "myplugin:1.2.3", "otherplugin:3.2.1":
	falcoctl registry push myrulesfile.tar.gz localhost:5000/myrulesfile:latest --type rulesfile \
		--depends-on myplugin:1.2.3 \
		--depends-on otherplugin:3.2.1
`

type pushOptions struct {
	*options.CommonOptions
	*options.ArtifactOptions
}

func (o pushOptions) validate() error {
	return o.ArtifactOptions.Validate()
}

func newPushProgressTracker(printer *output.Printer) ocipusher.ProgressTracker {
	return func(target oras.Target) oras.Target {
		return output.NewProgressTracker(printer, target, "Pushing")
	}
}

// NewPushCmd returns the push command.
func NewPushCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := pushOptions{
		CommonOptions:   opt,
		ArtifactOptions: &options.ArtifactOptions{},
	}

	cmd := &cobra.Command{
		Use:                   "push file hostname/repo[:tag|@digest] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Push a Falco OCI artifact to remote registry",
		Long:                  longPush,
		Args:                  cobra.ExactArgs(2),
		SilenceErrors:         true,
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.validate())
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunPush(ctx, args))
		},
	}
	o.CommonOptions.AddFlags(cmd.Flags())
	o.Printer.CheckErr(o.ArtifactOptions.AddFlags(cmd))
	return cmd
}

// RunPush executes the business logic for the push command.
func (o *pushOptions) RunPush(ctx context.Context, args []string) error {
	path := args[0]
	ref := args[1]
	o.Printer.Info.Printfln("Preparing to push artifact %q of type %q", args[0], o.ArtifactType)

	registry, err := utils.GetRegistryFromRef(ref)
	if err != nil {
		return err
	}

	o.Printer.Verbosef("Retrieving credentials from local store")
	credentialStore, err := authn.NewStore([]string{}...)
	if err != nil {
		return err
	}
	cred, err := credentialStore.Credential(ctx, registry)
	if err != nil {
		return err
	}

	if err := utils.CheckRegistryConnection(ctx, &cred, registry, o.Printer); err != nil {
		o.Printer.Verbosef("%s", err.Error())
		return fmt.Errorf("unable to connect to registry %q", registry)
	}

	client := authn.NewClient(cred)

	pusher := ocipusher.NewPusher(client, newPushProgressTracker(o.Printer))

	res, err := pusher.Push(ctx, o.ArtifactType, path, ref, o.Platform, o.Dependencies...)
	if err != nil {
		return err
	}

	o.Printer.Success.Printfln("Artifact pushed. Digest: %q", res.Digest)

	return nil
}
