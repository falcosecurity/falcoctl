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
	ocipuller "github.com/falcosecurity/falcoctl/pkg/oci/puller"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

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
		Use:                   "pull hostname/repo:tag",
		DisableFlagsInUseLine: true,
		Short:                 "Pull a Falco OCI artifact from a registry",
		Long:                  "Pull Falco rules or plugins OCI artifacts from a registry",
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
	cmd.Flags().StringVarP(&o.destDir, "dest-dir", "o", "", "destination dir where to save the artifacts")
	return cmd
}

// RunPull executes the business logic for the pull command.
func (o *pullOptions) RunPull(ctx context.Context, args []string) error {
	ref := args[0]

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

	puller := ocipuller.NewPuller(client)

	res, err := puller.Pull(ctx, o.ArtifactType, ref, o.destDir, o.GetOS(), o.GetArch())
	if err != nil {
		o.Printer.Error.Println(err.Error())
		return err
	}

	o.Printer.DefaultText.Printf("Artifact pulled. Digest: %s\n", res.Digest)
	return nil
}
