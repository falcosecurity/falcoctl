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

package options

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

// ArtifactOptions artifact specific options. Commands that need these options
// may embed this struct in their options.
type ArtifactOptions struct {
	ArtifactType oci.ArtifactType
	Platform     string
	Dependencies []string
}

var platformRgx = regexp.MustCompile(`^[a-z]+/[a-z0-9_]+$`)

// Validate validates the options passed by the user.
func (art *ArtifactOptions) Validate() error {
	switch art.ArtifactType {
	case oci.Plugin:
		if ok := platformRgx.MatchString(art.Platform); !ok {
			return fmt.Errorf("platform %q seems to be in the wrong format: needs to be in OS/ARCH "+
				"and to satisfy the following regexp %s", art.Platform, platformRgx.String())
		}
	default:
		// should never happen since we already validate the artifact type ad parsing time.
		return fmt.Errorf("unsupported artifact type: must be one of rule or plugin")
	}

	return nil
}

// AddFlags registers the artifacts flags.
func (art *ArtifactOptions) AddFlags(cmd *cobra.Command) error {
	cmd.Flags().VarP(&art.ArtifactType, "type", "t",
		`type of artifact to be pushed. Allowed values: "rulesfile", "plugin"`)
	if err := cmd.MarkFlagRequired("type"); err != nil {
		// this should never happen.
		return fmt.Errorf("unable to mark flag \"type\" as required: %w", err)
	}

	cmd.Flags().StringVar(&art.Platform, "platform", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		"os and architecture of the artifact in OS/ARCH format(only for plugins artifacts)")

	// If the command is the pull one, then do not add the "depends-on" flag.
	if cmd.Name() != "pull" {
		cmd.Flags().StringArrayVarP(&art.Dependencies, "depends-on", "d", []string{},
			`set an artifact dependency (can be specified multiple times). Example: "--depends-on my-plugin:1.2.3"`)
	}

	return nil
}

// GetOS return the operating system taken from platform.
func (art *ArtifactOptions) GetOS() string {
	tokens := strings.Split(art.Platform, "/")
	return tokens[0]
}

// GetArch return the architecture taken from platform.
func (art *ArtifactOptions) GetArch() string {
	tokens := strings.Split(art.Platform, "/")
	return tokens[1]
}
