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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	ocipusher "github.com/falcosecurity/falcoctl/pkg/oci/pusher"
	ociutils "github.com/falcosecurity/falcoctl/pkg/oci/utils"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	longPush = `Push Falco "rulesfile" or "plugin" OCI artifacts to remote registry

Example - Push artifact "myplugin.tar.gz" of type "plugin" for the platform where falcoctl is running (default):
	falcoctl registry push --type plugin --version "1.2.3" localhost:5000/myplugin:latest myplugin.tar.gz

Example - Push artifact "myplugin.tar.gz" of type "plugin" for platform "linux/arm64":
	falcoctl registry push --type plugin --version "1.2.3" localhost:5000/myplugin:latest myplugin.tar.gz --platform linux/arm64

Example - Push artifact "myplugin.tar.gz" of type "plugin" for multiple platforms:
	falcoctl registry push --type plugin --version "1.2.3" localhost:5000/myplugin:latest \
		myplugin-linux-x86_64.tar.gz --platform linux/x86_64 \
		myplugin-linux-arm64.tar.gz --platform linux/arm64

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile":
	falcoctl registry push --type rulesfile --version "0.1.2" localhost:5000/myrulesfile:latest myrulesfile.tar.gz

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" to an insecure registry:
	falcoctl registry push --type rulesfile --version "0.1.2" --plain-http localhost:5000/myrulesfile:latest myrulesfile.tar.gz

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with a dependency "myplugin:1.2.3":
	falcoctl registry push --type rulesfile --version "0.1.2" localhost:5000/myrulesfile:latest myrulesfile.tar.gz \
	        --depends-on myplugin:1.2.3

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with a dependency "myplugin:1.2.3" and an alternative "otherplugin:3.2.1":
	falcoctl registry push --type rulesfile --version "0.1.2" localhost:5000/myrulesfile:latest myrulesfile.tar.gz \
	        --depends-on "myplugin:1.2.3|otherplugin:3.2.1"

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with multiple dependencies "myplugin:1.2.3", "otherplugin:3.2.1":
        falcoctl registry push --type rulesfile --version "0.1.2" localhost:5000/myrulesfile:latest myrulesfile.tar.gz \
		--depends-on myplugin:1.2.3 \
		--depends-on otherplugin:3.2.1
`
)

type pushOptions struct {
	*options.Common
	*options.Artifact
	*options.Registry
}

func (o pushOptions) validate() error {
	return o.Artifact.Validate()
}

// NewPushCmd returns the push command.
func NewPushCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := pushOptions{
		Common:   opt,
		Artifact: &options.Artifact{},
		Registry: &options.Registry{},
	}

	cmd := &cobra.Command{
		Use:                   "push hostname/repo[:tag|@digest] file [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Push a Falco OCI artifact to remote registry",
		Long:                  longPush,
		Args:                  cobra.MinimumNArgs(2),
		SilenceErrors:         true,
		SilenceUsage:          true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
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
			return o.runPush(ctx, args)
		},
	}
	o.Registry.AddFlags(cmd)
	output.ExitOnErr(o.Printer, o.Artifact.AddFlags(cmd))

	return cmd
}

// runPush executes the business logic for the push command.
func (o *pushOptions) runPush(ctx context.Context, args []string) error {
	ref := args[0]
	paths := args[1:]
	// When creating the tar.gz archives we need to remove them after we are done.
	// We save the temporary dir where they live here.
	var toBeDeleted string

	registry, err := utils.GetRegistryFromRef(ref)
	if err != nil {
		return err
	}

	pusher, err := ociutils.Pusher(o.PlainHTTP, o.Printer)
	if err != nil {
		return fmt.Errorf("an error occurred while creating the pusher for registry %s: %w", registry, err)
	}

	err = ociutils.CheckConnectionForRegistry(ctx, pusher.Client, o.PlainHTTP, registry)
	if err != nil {
		return err
	}

	o.Printer.Info.Printfln("Preparing to push artifact %q of type %q", args[0], o.ArtifactType)

	// Make sure to remove temporary working dir.
	defer func() {
		if err := os.RemoveAll(toBeDeleted); err != nil {
			o.Printer.Warning.Printfln("Unable to remove temporary dir %q: %s", toBeDeleted, err.Error())
		}
	}()

	for i, p := range paths {
		if err = utils.IsTarGz(filepath.Clean(p)); err != nil && !errors.Is(err, utils.ErrNotTarGz) {
			return err
		} else if err == nil {
			continue
		} else {
			path, err := utils.CreateTarGzArchive(p)
			if err != nil {
				return err
			}
			paths[i] = path
			if toBeDeleted == "" {
				toBeDeleted = filepath.Dir(path)
			}
		}
	}

	// Setup OCI artifact configuration
	config := oci.ArtifactConfig{
		Name:    o.Name,
		Version: o.Version,
	}
	if config.Name == "" {
		// extract artifact name from ref, if not provided by the user
		if config.Name, err = utils.NameFromRef(ref); err != nil {
			return err
		}
	}
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
