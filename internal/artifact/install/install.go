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
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/index"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type artifactInstallOptions struct {
	*options.CommonOptions
	*options.RegistryOptions
	rulesfilesDir string
	pluginsDir    string
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
		Long:                  "Install a list of artifacts",
		PreRun: func(cmd *cobra.Command, args []string) {
			// Override "rulesfiles-dir" flag with viper config if not set by user.
			f := cmd.Flags().Lookup("rulesfiles-dir")
			if f == nil {
				// should never happen
				o.Printer.CheckErr(fmt.Errorf("unable to retrieve flag rulesfiles-dir"))
			} else if !f.Changed && viper.IsSet(config.InstallerRulesfilesDirKey) {
				val := viper.Get(config.InstallerRulesfilesDirKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					o.Printer.CheckErr(fmt.Errorf("unable to overwrite \"rulesfiles-dir\" flag: %w", err))
				}
			}

			// Override "plugins-dir" flag with viper config if not set by user.
			f = cmd.Flags().Lookup("plugins-dir")
			if f == nil {
				// should never happen
				o.Printer.CheckErr(fmt.Errorf("unable to retrieve flag plugins-dir"))
			} else if !f.Changed && viper.IsSet(config.InstallerPluginsDirKey) {
				val := viper.Get(config.InstallerPluginsDirKey)
				if err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val)); err != nil {
					o.Printer.CheckErr(fmt.Errorf("unable to overwrite \"plugins-dir\" flag: %w", err))
				}
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunArtifactInstall(ctx, args))
		},
	}

	o.RegistryOptions.AddFlags(cmd)
	cmd.Flags().StringVarP(&o.rulesfilesDir, "rulesfiles-dir", "", config.RulesfilesDir,
		"directory where to install rules. Defaults to /etc/falco")
	cmd.Flags().StringVarP(&o.pluginsDir, "plugins-dir", "", config.PluginsDir,
		"directory where to install plugins. Defaults to /usr/share/falco/plugins")

	return cmd
}

// RunArtifactInstall executes the business logic for the artifact install command.
func (o *artifactInstallOptions) RunArtifactInstall(ctx context.Context, args []string) error {
	if len(args) == 0 {
		configuredInstaller, err := config.Installer()
		if err != nil {
			o.Printer.CheckErr(fmt.Errorf("unable to retrieved the configured installer: %w", err))
		}

		args = configuredInstaller.Artifacts
	}

	o.Printer.Info.Printfln("Reading all configured index files from %q", config.IndexesFile)
	indexConfig, err := index.NewConfig(config.IndexesFile)
	if err != nil {
		return err
	}

	mergedIndexes, err := utils.Indexes(indexConfig, config.IndexesDir)
	if err != nil {
		return err
	}

	if len(mergedIndexes.Entries) < 1 {
		o.Printer.Warning.Println("No configured index. Consider to configure one using the 'index add' command.")
	}

	// Create temp dir where to put pulled artifacts
	tmpDir, err := os.MkdirTemp("", "falcoctl")
	if err != nil {
		return fmt.Errorf("cannot create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Specify how to pull config layer for each artifact requested by user.
	resolver := artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
		ref, err := utils.ParseReference(mergedIndexes, ref)
		if err != nil {
			return nil, err
		}

		reg, err := utils.GetRegistryFromRef(ref)
		if err != nil {
			return nil, err
		}

		puller, err := utils.PullerForRegistry(ctx, reg, o.PlainHTTP, o.Printer)
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

	// Compute input to install dependencies
	for i, arg := range args {
		args[i], err = utils.ParseReference(mergedIndexes, arg)
		if err != nil {
			return err
		}
	}

	// Solve dependencies
	o.Printer.Info.Println("Resolving dependencies ...")
	resolvedDepsRefs, err := ResolveDeps(resolver, args...)
	if err != nil {
		return err
	}

	o.Printer.Info.Printfln("Installing the following artifacts: %v", resolvedDepsRefs)

	// Install artifacts
	for _, ref := range resolvedDepsRefs {
		ref, err = utils.ParseReference(mergedIndexes, ref)
		if err != nil {
			return err
		}

		o.Printer.Info.Printfln("Preparing to pull %q", ref)

		reg, err := utils.GetRegistryFromRef(ref)
		if err != nil {
			return err
		}

		puller, err := utils.PullerForRegistry(ctx, reg, o.PlainHTTP, o.Printer)
		if err != nil {
			return err
		}

		// Install will always install artifact for the current OS and architecture
		result, err := puller.Pull(ctx, ref, tmpDir, runtime.GOOS, runtime.GOARCH)
		if err != nil {
			return err
		}

		var destDir string
		switch result.Type {
		case oci.Plugin:
			destDir = o.pluginsDir
		case oci.Rulesfile:
			destDir = o.rulesfilesDir
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
