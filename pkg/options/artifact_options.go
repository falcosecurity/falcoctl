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
	"strings"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

// ArtifactOptions artifact specific options. Commands that need these options
// may embed this struct in their options.
type ArtifactOptions struct {
	ArtifactType     oci.ArtifactType
	Name             string
	Platforms        []string // orders matter (same as args)
	Dependencies     []string
	Requirements     []string
	Tags             []string
	AnnotationSource string
}

var platformRgx = regexp.MustCompile(`^[a-z]+/[a-z0-9_]+$`)

// Validate validates the options passed by the user.
func (art *ArtifactOptions) Validate() error {
	for _, platform := range art.Platforms {
		if ok := platformRgx.MatchString(platform); !ok {
			return fmt.Errorf("platform %q seems to be in the wrong format: needs to be in OS/ARCH "+
				"and to satisfy the following regexp %s", platform, platformRgx.String())
		}
	}
	// TODO: cannot check that len(platforms) matches len(filepaths) here

	return nil
}

// AddFlags registers the artifacts flags.
func (art *ArtifactOptions) AddFlags(cmd *cobra.Command) error {
	cmd.Flags().StringArrayVar(&art.Platforms, "platform", nil,
		"os and architecture of the artifact in OS/ARCH format (only for plugins artifacts)")

	// Add the "depends-on" flag for "push" command only.
	switch cmd.Name() {
	case "push":
		cmd.Flags().StringArrayVarP(&art.Tags, "tag", "t", nil,
			"additional artifact tag. Can be repeated multiple times")

		cmd.Flags().Var(&art.ArtifactType, "type",
			`type of artifact to be pushed. Allowed values: "rulesfile", "plugin"`)
		if err := cmd.MarkFlagRequired("type"); err != nil {
			// this should never happen.
			return fmt.Errorf("unable to mark flag \"type\" as required: %w", err)
		}

		cmd.Flags().StringArrayVarP(&art.Requirements, "requires", "r", nil,
			`set an artifact requirement (can be specified multiple times). Example: "--requires plugin_api_version:1.2.3"`)

		cmd.Flags().StringArrayVarP(&art.Dependencies, "depends-on", "d", nil,
			`set an artifact dependency (can be specified multiple times). Example: "--depends-on my-plugin:1.2.3"`)

		cmd.Flags().StringVar(&art.AnnotationSource, "annotation-source", "",
			`set annotation source for the artifact`)

		cmd.Flags().StringVar(&art.Name, "name", "",
			`set the unique name of the artifact (if not set, the name is extracted from the reference)`)

	case "pull":
		if len(art.Platforms) > 1 {
			return fmt.Errorf("--platform can be specified only one time for pull")
		}
	}

	return nil
}

// OSArch returns the OS and the ARCH of the platform at index-th position.
func (art *ArtifactOptions) OSArch(index int) (os, arch string) {
	if index >= len(art.Platforms) || index < 0 {
		return "", ""
	}

	tokens := strings.Split(art.Platforms[index], "/")
	return tokens[0], tokens[1]
}
