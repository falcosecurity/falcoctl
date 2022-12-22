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

package push

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

var longPush = `Push Falco "rulefile" or "plugin" OCI artifacts to remote registry

Example - Push artifact "myplugin.tar.gz" of type "plugin" for the platform where falcoctl is running (default):
	falcoctl registry push --type plugin localhost:5000/myplugin:latest myplugin.tar.gz

Example - Push artifact "myplugin.tar.gz" of type "plugin" for platform "linux/aarch64":
	falcoctl registry push --type plugin localhost:5000/myplugin:latest myplugin.tar.gz --platform linux/aarch64

Example - Push artifact "myplugin.tar.gz" of type "plugin" for multiple platforms:
	falcoctl registry push --type plugin localhost:5000/myplugin:latest \
		myplugin-linux-x86_64.tar.gz --platform linux/x86_64 \
		myplugin-linux-arm64.tar.gz --platform linux/aarch64

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile":
	falcoctl registry push --type rulesfile localhost:5000/myrulesfile:latest myrulesfile.tar.gz

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with a dependency "myplugin:1.2.3":
	falcoctl registry push --type rulesfile localhost:5000/myrulesfile:latest myrulesfile.tar.gz --depends-on myplugin:1.2.3

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with a dependency "myplugin:1.2.3" and an alternative "otherplugin:3.2.1":
	falcoctl registry push --type rulesfile localhost:5000/myrulesfile:latest myrulesfile.tar.gz --depends-on "myplugin:1.2.3|otherplugin:3.2.1"

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with multiple dependencies "myplugin:1.2.3", "otherplugin:3.2.1":
    falcoctl registry push --type rulesfile localhost:5000/myrulesfile:latest myrulesfile.tar.gz \
		--depends-on myplugin:1.2.3 \
		--depends-on otherplugin:3.2.1
`

type pushOptions struct {
	*options.CommonOptions
	*options.ArtifactOptions
	*options.RegistryOptions
}

func (o pushOptions) validate() error {
	return o.ArtifactOptions.Validate()
}

// NewPushCmd returns the push command.
func NewPushCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := pushOptions{
		CommonOptions:   opt,
		ArtifactOptions: &options.ArtifactOptions{},
		RegistryOptions: &options.RegistryOptions{},
	}

	cmd := &cobra.Command{
		Use:                   "push hostname/repo[:tag|@digest] file [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Push a Falco OCI artifact to remote registry",
		Long:                  longPush,
		Args:                  cobra.MinimumNArgs(2),
		SilenceErrors:         true,
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.validate())
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunPush(ctx, args))
		},
	}
	o.CommonOptions.AddFlags(cmd.Flags())
	o.RegistryOptions.AddFlags(cmd)
	o.Printer.CheckErr(o.ArtifactOptions.AddFlags(cmd))

	return cmd
}

// RunPush executes the business logic for the push command.
func (o *pushOptions) RunPush(ctx context.Context, args []string) error {
	ref := args[0]
	paths := args[1:]
	o.Printer.Info.Printfln("Preparing to push artifact %q of type %q", args[0], o.ArtifactType)

	registry, err := utils.GetRegistryFromRef(ref)
	if err != nil {
		return err
	}

	pusher, err := utils.PusherForRegistry(ctx, o.PlainHTTP, o.Oauth, registry, o.Printer)
	if err != nil {
		return fmt.Errorf("an error occurred while creating the pusher for registry %s: %w", registry, err)
	}

	// Setup OCI artifact configuration
	config := oci.ArtifactConfig{}
	if err := config.ParseDependencies(o.Dependencies...); err != nil {
		return err
	}
	if err := config.ParseRequirements(o.Requirements...); err != nil {
		return err
	}

	opts := ocipusher.Options{
		ocipusher.WithTags(o.Tags...),
		ocipusher.WithAnnotationSource(o.AnnotationSource),
		ocipusher.WithArtifactConfig(config),
	}

	switch o.ArtifactType {
	case oci.Plugin:
		opts = append(opts, ocipusher.WithFilepathsAndPlatforms(paths, o.Platforms))
	case oci.Rulesfile:
		opts = append(opts, ocipusher.WithFilepaths(paths))
	}

	res, err := pusher.Push(ctx, o.ArtifactType, ref, opts...)
	if err != nil {
		return err
	}

	o.Printer.Success.Printfln("Artifact pushed. Digest: %q", res.Digest)

	return nil
}
