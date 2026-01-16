// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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
	"errors"
	"fmt"

	"github.com/blang/semver"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

type artifactConfigResolver func(ref string) (*oci.ArtifactConfig, error)
type refResolver func(ref string) (string, error)

// ArtifactMapType maps artifact names to their metadata.
type ArtifactMapType map[string]*ArtifactInfo

var (
	// ErrCannotSatisfyDependencies is the error returned when we cannot correctly resolve dependencies.
	ErrCannotSatisfyDependencies = errors.New("cannot satisfy dependencies")
)

// ArtifactInfo contains metadata about a resolved artifact.
type ArtifactInfo struct {
	// ref is the remote reference to this artifact
	ref string
	// config contains the config layer for this artifact
	config *oci.ArtifactConfig
	// ver represents the semver version of this artifact
	ver *semver.Version
	// ok is used to mark this artifact as fully processed, with its own
	// dependencies and alternatives
	ok bool
}

func copyArtifactMap(in ArtifactMapType) (out ArtifactMapType) {
	out = make(ArtifactMapType, len(in))
	for k, v := range in {
		out[k] = v
	}
	return
}

// ResolveDeps resolves dependencies to a list of references.
func ResolveDeps(configResolver artifactConfigResolver, resolver refResolver, inRefs ...string) (artifacts ArtifactMapType, err error) {
	depMap := make(ArtifactMapType)

	upsertMap := func(ref string) error {
		// fetch artifact config layer metadata
		config, err := configResolver(ref)
		if err != nil {
			return err
		}

		if config.Version == "" {
			return fmt.Errorf("empty version for ref %q: config may be corrupted", ref)
		}

		ver, err := semver.ParseTolerant(config.Version)
		if err != nil {
			return fmt.Errorf("unable to parse version %q for ref %q, %w", config.Version, ref, err)
		}

		depMap[config.Name] = &ArtifactInfo{
			ref:    ref,
			config: config,
			ver:    &ver,
		}
		return nil
	}

	// Prepare initial map from user inputs
	for _, ref := range inRefs {
		if err := upsertMap(ref); err != nil {
			return nil, err
		}
	}

	for {
		allOk := true
		// Since we are updating depMap in this for loop, let's copy the map for iterating it
		// while we continue inserting new values in the real depMap map.
		for name, info := range copyArtifactMap(depMap) {
			if info.ok {
				continue
			}
			for _, required := range info.config.Dependencies {
				// Does already exist in the map?
				if existing, ok := depMap[required.Name]; ok {
					requiredVer, err := semver.ParseTolerant(required.Version)
					if err != nil {
						return nil, fmt.Errorf(`invalid artifact config: version %q is not semver compatible`, required.Version)
					}

					// Is the existing dep compatible?
					if existing.ver.Major != requiredVer.Major {
						return nil, fmt.Errorf(
							`%w: %s depends on %s:%s but an incompatible version %s:%s is required by other artifacts`,
							ErrCannotSatisfyDependencies, name, required.Name, required.Version, required.Name, existing.ver.String(),
						)
					}

					// Is required version greater than existing one?
					if requiredVer.Compare(*existing.ver) <= 0 {
						continue
					}
				}

				// Are alternatives already in the map?
				var foundAlternative = false
				for _, alternative := range required.Alternatives {
					existing, ok := depMap[alternative.Name]
					if !ok {
						continue
					}

					foundAlternative = true

					alternativeVer, err := semver.ParseTolerant(alternative.Version)
					if err != nil {
						return nil, fmt.Errorf(`invalid artifact config: version %q is not semver compatible`, alternative.Version)
					}

					// Is the alternative specified by the user compatible?
					if existing.ver.Major != alternativeVer.Major {
						return nil, fmt.Errorf(
							`%w: %s depends on %s:%s but an incompatible version %s:%s is required by other artifacts`,
							ErrCannotSatisfyDependencies, name, required.Name, required.Version, alternative.Name, existing.ver.String(),
						)
					}

					if alternativeVer.Compare(*existing.ver) > 0 {
						resolvedAlternative, err := resolver(alternative.Name + ":" + alternative.Version)
						if err != nil {
							return nil, fmt.Errorf("unable to resolve reference for alternative dependency %q required by %q: %w", alternative.Name, name, err)
						}

						if err := upsertMap(resolvedAlternative); err != nil {
							return nil, err
						}
					}

					break
				}
				if foundAlternative {
					continue
				}

				resolved, err := resolver(required.Name + ":" + required.Version)
				if err != nil {
					return nil, fmt.Errorf("unable to resolve reference for dependency %q required by %q: %w", required.Name, name, err)
				}

				// dep to be added or bumped
				if err := upsertMap(resolved); err != nil {
					return nil, err
				}
				allOk = false
			}

			// dep processed
			info.ok = true
		}

		if allOk {
			return depMap, nil
		}
	}
}
