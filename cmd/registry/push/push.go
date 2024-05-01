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

package push

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/blang/semver/v4"
	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

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

Example - Push artifact "myrulesfile.tar.gz" of type "rulesfile" with floating tags for the major and minor versions (0 and 0.1):
	falcoctl registry push --type rulesfile --version "0.1.2" localhost:5000/myrulesfile:latest myrulesfile.tar.gz \
	        --add-floating-tags

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

func (o *pushOptions) validate() error {
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
	// Holds the path for each temporary dir.
	var toBeDeletedTmpDirs []string
	logger := o.Printer.Logger

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

	logger.Info("Preparing to push artifact", o.Printer.Logger.Args("name", args[0], "type", o.ArtifactType))

	// Make sure to remove temporary working dirs.
	defer func() {
		for _, dir := range toBeDeletedTmpDirs {
			logger.Debug("Removing temporary dir", logger.Args("name", dir))
			if err := os.RemoveAll(dir); err != nil {
				logger.Warn("Unable to remove temporary dir", logger.Args("name", dir, "error", err.Error()))
			}
		}
	}()

	config := &oci.ArtifactConfig{
		Name:    o.Name,
		Version: o.Version,
	}

	for i, p := range paths {
		if err = utils.IsTarGz(filepath.Clean(p)); err != nil && !errors.Is(err, utils.ErrNotTarGz) {
			return err
		} else if err == nil {
			continue
		} else {
			if o.ArtifactType == oci.Rulesfile {
				if config, err = rulesConfigLayer(o.Printer.Logger, p, o.Artifact); err != nil {
					return err
				}
			}
			path, err := utils.CreateTarGzArchive("", p)
			if err != nil {
				return err
			}
			paths[i] = path
			toBeDeletedTmpDirs = append(toBeDeletedTmpDirs, filepath.Dir(path))
		}
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

	if o.AutoFloatingTags {
		v, err := semver.Parse(o.Version)
		if err != nil {
			return fmt.Errorf("expected semver for the flag \"--version\": %w", err)
		}
		o.Tags = append(o.Tags, o.Version, fmt.Sprintf("%v", v.Major), fmt.Sprintf("%v.%v", v.Major, v.Minor))
	}

	opts := ocipusher.Options{
		ocipusher.WithTags(o.Tags...),
		ocipusher.WithAnnotationSource(o.AnnotationSource),
		ocipusher.WithArtifactConfig(*config),
	}

	switch o.ArtifactType {
	case oci.Plugin:
		opts = append(opts, ocipusher.WithFilepathsAndPlatforms(paths, o.Platforms))
	case oci.Rulesfile:
		opts = append(opts, ocipusher.WithFilepaths(paths))
	case oci.Asset:
		opts = append(opts, ocipusher.WithFilepaths(paths))
	}

	res, err := pusher.Push(ctx, o.ArtifactType, ref, opts...)
	if err != nil {
		return err
	}

	logger.Info("Artifact pushed", logger.Args("name", args[0], "type", res.Type, "digest", res.RootDigest))

	return nil
}

const (
	// depsKey is the key for deps in the rulesfiles.
	depsKey = "required_plugin_versions"
	// engineKey is the key in the rulesfiles.
	engineKey = "required_engine_version"
	// engineRequirementKey is used as name for the engine requirement in the config layer for the rulesfile artifacts.
	engineRequirementKey = "engine_version_semver"
)

func rulesConfigLayer(logger *pterm.Logger, filePath string, artifactOptions *options.Artifact) (*oci.ArtifactConfig, error) {
	var data []map[string]interface{}

	// Setup OCI artifact configuration
	config := oci.ArtifactConfig{
		Name:    artifactOptions.Name,
		Version: artifactOptions.Version,
	}

	yamlFile, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, fmt.Errorf("unable to open rulesfile %s: %w", filePath, err)
	}

	if err := yaml.Unmarshal(yamlFile, &data); err != nil {
		return nil, fmt.Errorf("unable to unmarshal rulesfile %s: %w", filePath, err)
	}

	// Parse the artifact dependencies.
	// Check if the user has provided any.
	if len(artifactOptions.Dependencies) != 0 {
		logger.Info("Dependencies provided by user", logger.Args("rulesfile", filePath))
		if err = config.ParseDependencies(artifactOptions.Dependencies...); err != nil {
			return nil, err
		}
	} else {
		// If no user provided then try to parse them from the rulesfile.
		var found bool
		logger.Info("Parsing dependencies from: ", logger.Args("rulesfile", filePath))
		var requiredPluginVersionsEntry interface{}
		var ok bool
		for _, entry := range data {
			if requiredPluginVersionsEntry, ok = entry[depsKey]; !ok {
				continue
			}

			var deps []oci.ArtifactDependency
			byteData, err := yaml.Marshal(requiredPluginVersionsEntry)
			if err != nil {
				return nil, fmt.Errorf("unable to parse dependencies from rulesfile: %w", err)
			}
			err = yaml.Unmarshal(byteData, &deps)
			if err != nil {
				return nil, fmt.Errorf("unable to parse dependencies from rulesfile: %w", err)
			}
			logger.Info("Dependencies correctly parsed from rulesfile")
			// Set the deps.
			config.Dependencies = deps
			found = true
			break
		}
		if !found {
			logger.Warn("No dependencies were provided by the user and none were found in the rulesfile.")
		}
	}

	// Parse the requirements.
	// Check if the user has provided any.
	if len(artifactOptions.Requirements) != 0 {
		logger.Info("Requirements provided by user")
		if err = config.ParseRequirements(artifactOptions.Requirements...); err != nil {
			return nil, err
		}
	} else {
		var found bool
		var engineVersion string
		logger.Info("Parsing requirements from: ", logger.Args("rulesfile", filePath))
		// If no user provided requirements then try to parse them from the rulesfile.
		for _, entry := range data {
			if requiredEngineVersionEntry, ok := entry[engineKey]; ok {
				// Check if the version is an int. This is for backward compatibility. The engine version used to be an
				// int but internally used by falco as a semver minor version.
				// 15 -> 0.15.0
				if engVersionInt, ok := requiredEngineVersionEntry.(int); ok {
					engineVersion = fmt.Sprintf("0.%d.0", engVersionInt)
				} else {
					engineVersion, ok = requiredEngineVersionEntry.(string)
					if !ok {
						return nil, fmt.Errorf("%s must be an int or a string respecting the semver specification, got type %T", engineKey, requiredEngineVersionEntry)
					}

					// Check if it is in semver format.
					if _, err := semver.Parse(engineVersion); err != nil {
						return nil, fmt.Errorf("%s must be in semver format: %w", engineVersion, err)
					}
				}

				// Set the requirements.
				config.Requirements = []oci.ArtifactRequirement{{
					Name:    engineRequirementKey,
					Version: engineVersion,
				}}
				found = true
				break
			}
		}
		if !found {
			logger.Warn("No requirements were provided by the user and none were found in the rulesfile.")
		}
	}

	return &config, nil
}
