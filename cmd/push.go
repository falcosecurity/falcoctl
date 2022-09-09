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

	"github.com/falcosecurity/falcoctl/cmd/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type pushOptions struct {
	*options.CommonOptions
	*options.ArtifactOptions
}

func (o pushOptions) validate() error {
	return o.ArtifactOptions.Validate()
}

// NewPushCmd returns the push command.
func NewPushCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := pushOptions{
		CommonOptions:   opt,
		ArtifactOptions: &options.ArtifactOptions{},
	}

	cmd := &cobra.Command{
		Use:                   "push filename hostname/repo:tag",
		DisableFlagsInUseLine: true,
		Short:                 "Push a Falco OCI artifact to a registry",
		Long:                  "Push Falco rules or plugins OCI artifacts to a registry",
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

	registry, err := utils.GetRegistryFromRef(ref)
	if err != nil {
		return err
	}

	credentialStore, err := authn.NewStore([]string{}...)
	if err != nil {
		return err
	}
	cred, err := credentialStore.Credential(ctx, registry)
	if err != nil {
		return err
	}
	client := authn.NewClient(cred)

	pusher, err := ocipusher.NewPusher(client)
	if err != nil {
		return err
	}

	res, err := pusher.Push(ctx, o.ArtifactType, path, ref, o.Platform, o.Dependencies...)
	if err != nil {
		return err
	}

	o.Printer.DefaultText.Printf("Artifact pushed. Digest: %s\n", res.Digest)

	return nil
}
