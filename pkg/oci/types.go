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

package oci

import (
	"errors"
	"strings"
)

// ArtifactType represents a rule or a plugin. Used to select the right mediaType when interacting with the registry.
type ArtifactType string

const (
	// Rulesfile represents a rule artifact.
	Rulesfile ArtifactType = "rulesfile"
	// Plugin represents a plugin artifact.
	Plugin ArtifactType = "plugin"
)

// The following functions are necessary to use ArtifactType with Cobra.

// String returns a string representation of ArtifactType.
func (e *ArtifactType) String() string {
	return string(*e)
}

// Set an ArtifactType.
func (e *ArtifactType) Set(v string) error {
	switch v {
	case "rulesfile", "plugin":
		*e = ArtifactType(v)
		return nil
	default:
		return errors.New(`must be one of "rulesfile", "plugin"`)
	}
}

// Type returns a string representing this type.
func (e *ArtifactType) Type() string {
	return "ArtifactType"
}

// RegistryResult represents a generic result that is generated when
// interacting with a remote OCI registry.
type RegistryResult struct {
	Digest string
	Config ArtifactConfig
}

// ArtifactConfig is the struct stored in the config layer of rulesfile and plugin artifacts. Each type fills only the fields of interest.
type ArtifactConfig struct {
	RequiredPluginVersions []dependency `json:"required_plugin_versions,omitempty"`
}

type dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SetRequiredPluginVersions sets the rulesfile to plugins dependencies to be stored in the config.
// Validation of dependency format is done in the cmd package.
func (rc *ArtifactConfig) SetRequiredPluginVersions(dependencies ...string) error {
	for _, dep := range dependencies {
		splittedDep := strings.Split(dep, ":")
		rc.RequiredPluginVersions = append(rc.RequiredPluginVersions, dependency{Name: splittedDep[0], Version: splittedDep[1]})
	}
	return nil
}
