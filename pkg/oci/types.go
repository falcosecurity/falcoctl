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
	"fmt"
	"sort"
	"strings"

	"github.com/falcosecurity/falcoctl/pkg/artifact"
)

// ArtifactType represents a rules file or a plugin. Used to select the right mediaType when interacting with the registry.
type ArtifactType string

const (
	// Rulesfile represents a rules file artifact.
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
	Digest   string
	Config   ArtifactConfig
	Type     ArtifactType
	Filename string
}

// ArtifactConfig is the struct stored in the config layer of rulesfile and plugin artifacts. Each type fills only the fields of interest.
type ArtifactConfig struct {
	Dependencies []ArtifactDependency `json:"dependencies,omitempty"`
}

type dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ArtifactDependency represents the artifact's depedendency to be stored in the config.
type ArtifactDependency struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Alternatives []dependency `json:"alternatives,omitempty"`
}

// SetAlternative sets an alternative dependency for an artifact dependency.
func (a *ArtifactDependency) SetAlternative(name, version string) {
	for i, d := range a.Alternatives {
		if d.Name == name {
			a.Alternatives[i].Version = version
			return
		}
	}

	// we could insert in the middle while looking for a dup...
	// ...but we are lazy.
	a.Alternatives = append(a.Alternatives, dependency{name, version})
	sort.Slice(a.Alternatives, func(i, j int) bool {
		return a.Alternatives[i].Name < a.Alternatives[j].Name
	})
}

// SetDepedency stores an artifact dependency in the config.
//
// Return the insertion position.
func (rc *ArtifactConfig) SetDepedency(name, version string) int {
	for i, d := range rc.Dependencies {
		if d.Name == name {
			rc.Dependencies[i].Version = version
			return i
		}
	}

	// we could insert in the middle while looking for a dup...
	// ...but we are lazy.
	rc.Dependencies = append(rc.Dependencies, ArtifactDependency{
		Name:    name,
		Version: version,
	})
	sort.Slice(rc.Dependencies, func(i, j int) bool {
		return rc.Dependencies[i].Name < rc.Dependencies[j].Name
	})
	return sort.Search(len(rc.Dependencies), func(i int) bool {
		return rc.Dependencies[i].Name >= name
	})
}

// ParseDependencies parses artifact dependencies in the format "name:version|alt1:version1|..." and set them in the config.
func (rc *ArtifactConfig) ParseDependencies(dependencies ...string) error {
	for _, d := range dependencies {
		artifactRefs := strings.Split(d, "|")
		var insertPos int
		for i, a := range artifactRefs {
			parsedRef, err := artifact.ParseRef(a)
			if err != nil {
				return fmt.Errorf(`cannot parse "%s": %w`, a, err)
			}
			// The first dependency is used to fill the "name" and "version" fields.
			// All the other dependencies, if any, are set as alternatives.
			if i == 0 {
				insertPos = rc.SetDepedency(parsedRef.Name, parsedRef.Version)
			} else {
				rc.Dependencies[insertPos].SetAlternative(parsedRef.Name, parsedRef.Version)
			}
		}
	}
	return nil
}
