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

package options

import (
	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/spf13/cobra"
)

const (
	// FlagRulesFilesDir is the name of the flag to specify the directory path of rules files.
	FlagRulesFilesDir = "rulesfiles-dir"

	// FlagPluginsFilesDir is the name of the flag to specify the directory path of plugins.
	FlagPluginsFilesDir = "plugins-dir"

	// FlagAssetsFilesDir is the name of the flag to specify the directory path of assets.
	FlagAssetsFilesDir = "assets-dir"
)

// Directory options for install directories for artifacts.
type Directory struct {
	// RulesfilesDir path where rule are installed
	RulesfilesDir string
	// PluginsDir path where plugins are installed
	PluginsDir string
	// AssetsDire path where assets are installed
	AssetsDir string
}

// AddFlags registers the directories flags.
func (o *Directory) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.RulesfilesDir, FlagRulesFilesDir, "", config.RulesfilesDir,
		"Directory where to install rules")
	cmd.Flags().StringVarP(&o.PluginsDir, FlagPluginsFilesDir, "", config.PluginsDir,
		"Directory where to install plugins")
	cmd.Flags().StringVarP(&o.AssetsDir, FlagAssetsFilesDir, "", config.AssetsDir,
		"Directory where to install assets")
}
