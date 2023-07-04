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

package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/sign"
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	ociutils "github.com/falcosecurity/falcoctl/pkg/oci/utils"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	longInstall = `This command allows you to install one or more given artifacts.

Artifact references and flags are passed as arguments through:
- command line options
- environment variables
- configuration file
The arguments passed through these different modalities are prioritized in the following order:
command line options, environment variables, and finally the configuration file. This means that
if an argument is passed through multiple modalities, the value set in the command line options
will take precedence over the value set in environment variables, which will in turn take precedence
over the value set in the configuration file.
Please note that when passing multiple artifact references via an environment variable, they must be
separated by a semicolon ';'. Other arguments, if passed through environment variables, should start
with "FALCOCTL_" and be followed by the hierarchical keys used in the configuration file separated by
an underscore "_".

A reference is either a simple name or a fully qualified reference ("<registry>/<repository>"), 
optionally followed by ":<tag>" (":latest" is assumed by default when no tag is given).

When providing just the name of the artifact, the command will search for the artifacts in 
the configured index files, and if found, it will use the registry and repository specified 
in the indexes.

Example - Install "latest" tag of "k8saudit-rules" artifact by relying on index metadata:
	falcoctl artifact install k8saudit-rules

Example - Install all updates from "k8saudit-rules" 0.5.x release series:
	falcoctl artifact install k8saudit-rules:0.5

Example - Install "cloudtrail" plugins using a fully qualified reference:
	falcoctl artifact install ghcr.io/falcosecurity/plugins/ruleset/k8saudit:latest
`
)

type artifactInstallOptions struct {
	*options.CommonOptions
	*options.RegistryOptions
	rulesfilesDir string
	pluginsDir    string
	allowedTypes  oci.ArtifactTypeSlice
	resolveDeps   bool
	noVerify      bool
}

// NewArtifactInstallCmd returns the artifact install command.
func NewArtifactInstallCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := artifactInstallOptions{
		CommonOptions:   opt,
		RegistryOptions: &options.RegistryOptions{},
	}

	cmd := &cobra.Command{
		Use:                   "install [ref1 [ref2 ...]] [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Install a list of artifacts",
		Long:                  longInstall,
		SilenceErrors:         true,
		SilenceUsage:          true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Override "rulesfiles-dir" flag with viper config if not set by user.
			f := cmd.Flags().Lookup(FlagRulesFilesDir)
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag %q", FlagRulesFilesDir)
			} else if !f.Changed && viper.IsSet(config.ArtifactInstallRulesfilesDirKey) {
				val := viper.Get(config.ArtifactInstallRulesfilesDirKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite %q flag: %w", FlagRulesFilesDir, err)
				}
			}

			// Override "plugins-dir" flag with viper config if not set by user.
			f = cmd.Flags().Lookup(FlagPluginsFilesDir)
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag %q", FlagPluginsFilesDir)
			} else if !f.Changed && viper.IsSet(config.ArtifactInstallPluginsDirKey) {
				val := viper.Get(config.ArtifactInstallPluginsDirKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite %q flag: %w", FlagPluginsFilesDir, err)
				}
			}

			// Override "allowed-types" flag with viper config if not set by user.
			f = cmd.Flags().Lookup(FlagAllowedTypes)
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag %q", FlagAllowedTypes)
			} else if !f.Changed && viper.IsSet(config.ArtifactAllowedTypesKey) {
				val, err := config.ArtifactAllowedTypes()
				if err != nil {
					return err
				}
				if err := cmd.Flags().Set(f.Name, val.String()); err != nil {
					return fmt.Errorf("unable to overwrite %s flag: %w", FlagAllowedTypes, err)
				}
			}

			f = cmd.Flags().Lookup(FlagResolveDeps)
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag %q", FlagResolveDeps)
			} else if !f.Changed && viper.IsSet(config.ArtifactInstallResolveDepsKey) {
				val := viper.Get(config.ArtifactInstallResolveDepsKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite %q flag: %w", FlagResolveDeps, err)
				}
			}

			f = cmd.Flags().Lookup(FlagNoVerify)
			if f == nil {
				// should never happen
				return fmt.Errorf("unable to retrieve flag %q", FlagNoVerify)
			} else if !f.Changed && viper.IsSet(config.ArtifactNoVerifyKey) {
				val := viper.Get(config.ArtifactNoVerifyKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					return fmt.Errorf("unable to overwrite %q flag: %w", FlagNoVerify, err)
				}
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunArtifactInstall(ctx, args)
		},
	}

	o.RegistryOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&o.rulesfilesDir, FlagRulesFilesDir, "", config.RulesfilesDir,
		"directory where to install rules.")
	cmd.Flags().StringVarP(&o.pluginsDir, FlagPluginsFilesDir, "", config.PluginsDir,
		"directory where to install plugins.")
	cmd.Flags().Var(&o.allowedTypes, FlagAllowedTypes,
		fmt.Sprintf(`list of artifact types that can be installed. If not specified or configured, all types are allowed.
It accepts comma separated values or it can be repeated multiple times.
Examples: 
	--%s="rulesfile,plugin"
	--%s=rulesfile --%s=plugin`, FlagAllowedTypes, FlagAllowedTypes, FlagAllowedTypes))
	cmd.Flags().BoolVar(&o.resolveDeps, FlagResolveDeps, true,
		"whether this command should resolve dependencies or not")
	cmd.Flags().BoolVar(&o.noVerify, FlagNoVerify, false,
		"whether this command should skip signature verification")

	return cmd
}

// RunArtifactInstall executes the business logic for the artifact install command.
func (o *artifactInstallOptions) RunArtifactInstall(ctx context.Context, args []string) error {
	// Retrieve configuration for installer
	configuredInstaller, err := config.Installer()
	if err != nil {
		return fmt.Errorf("unable to retrieve the configured installer: %w", err)
	}

	// Set args as configured if no arg was passed
	if len(args) == 0 {
		if len(configuredInstaller.Artifacts) == 0 {
			return fmt.Errorf("no artifacts to install, please configure artifacts or pass them as arguments to this command")
		}
		args = configuredInstaller.Artifacts
	}

	// Create temp dir where to put pulled artifacts
	tmpDir, err := os.MkdirTemp("", "falcoctl")
	if err != nil {
		return fmt.Errorf("cannot create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create registry puller with auto login enabled
	puller, err := ociutils.Puller(o.PlainHTTP, o.Printer)
	if err != nil {
		return err
	}

	// Specify how to pull config layer for each artifact requested by user.
	resolver := artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
		ref, err := o.IndexCache.ResolveReference(ref)
		if err != nil {
			return nil, err
		}

		artifactConfig, err := puller.PullConfigLayer(ctx, ref)
		if err != nil {
			return nil, err
		}

		return &oci.RegistryResult{
			Config: *artifactConfig,
		}, nil
	})

	signatures := make(map[string]*index.Signature)

	// Compute input to install dependencies
	for i, arg := range args {
		ref, err := o.IndexCache.ResolveReference(arg)
		if err != nil {
			return err
		}
		if sig := o.IndexCache.SignatureForIndexRef(arg); sig != nil {
			signatures[ref] = sig
		}
		args[i] = ref
	}

	var refs []string
	if o.resolveDeps {
		// Solve dependencies
		o.Printer.Info.Println("Resolving dependencies ...")
		refs, err = ResolveDeps(resolver, args...)
		if err != nil {
			return err
		}
	} else {
		refs = args
	}

	o.Printer.Info.Printfln("Installing the following artifacts: %v", refs)

	for _, ref := range refs {
		var sig *index.Signature
		ref, err = o.IndexCache.ResolveReference(ref)
		if err != nil {
			return err
		}
		sig, ok := signatures[ref]
		if !ok {
			// try to get the signature from the index
			o.IndexCache.SignatureForIndexRef(ref)
		}

		repo, err := utils.RepositoryFromRef(ref)
		if err != nil {
			return err
		}

		o.Printer.Info.Printfln("Preparing to pull %q", ref)

		if err := puller.CheckAllowedType(ctx, ref, o.allowedTypes.Types); err != nil {
			return err
		}

		// Install will always install artifact for the current OS and architecture
		result, err := puller.Pull(ctx, ref, tmpDir, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return err
		}

		// In order to prevent TOCTOU issues we'll perform signature verification after we complete a pull
		// and obtained a digest but before files are written to disk. This way we ensure that we're verifying
		// the exact digest that we just pulled, even if the tag gets overwritten in the meantime.
		digestRef := fmt.Sprintf("%s@%s", repo, result.RootDigest)

		if sig != nil && !o.noVerify {
			o.Printer.Info.Printfln("Verifying signature for %s", digestRef)
			err = sign.VerifySignature(digestRef, sig)
			if err != nil {
				return fmt.Errorf("error while verifying signature for %s: %w", digestRef, err)
			}
			o.Printer.Info.Printfln("Signature successfully verified!")
		}

		var destDir string
		switch result.Type {
		case oci.Plugin:
			destDir = o.pluginsDir
		case oci.Rulesfile:
			destDir = o.rulesfilesDir
		}

		// Check if directory exists and is writable.
		err = utils.ExistsAndIsWritable(destDir)
		if err != nil {
			return fmt.Errorf("cannot use directory %q as install destination: %w", destDir, err)
		}

		sp, _ := o.Printer.Spinner.Start(fmt.Sprintf("INFO: Extracting and installing %q %q", result.Type, result.Filename))
		result.Filename = filepath.Join(tmpDir, result.Filename)

		f, err := os.Open(result.Filename)
		if err != nil {
			return err
		}

		// Extract artifact and move it to its destination directory
		_, err = utils.ExtractTarGz(f, destDir)
		if err != nil {
			return fmt.Errorf("cannot extract %q to %q: %w", result.Filename, destDir, err)
		}

		err = os.Remove(result.Filename)
		if err != nil {
			return err
		}

		sp.Success(fmt.Sprintf("Artifact successfully installed in %q", destDir))
	}

	return nil
}
