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

package install

import (
	"errors"
	"fmt"

	"github.com/blang/semver"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

type artifactConfigResolver func(ref string) (*oci.RegistryResult, error)
type depsMapType map[string]*depInfo

var (
	// ErrCannotSatisfyDependencies is the error returned when we cannot correctly resolve dependencies.
	ErrCannotSatisfyDependencies = errors.New("cannot satisfy dependencies")
)

type depInfo struct {
	// ref is the remote reference to this artifact
	ref string
	// config contains the config layer for this artifact
	config *oci.ArtifactConfig
	// ver represents the semver version of this artifact
	ver *semver.Version
	// ok is used to mark this dependency as fully processed, with its own
	// dependencies and alternatives
	ok bool
}

func copyDepsMap(in depsMapType) (out depsMapType) {
	out = make(depsMapType, len(in))
	for k, v := range in {
		out[k] = v
	}
	return
}

// ResolveDeps resolves dependencies to a list of references.
func ResolveDeps(resolver artifactConfigResolver, inRefs ...string) (outRefs []string, err error) {
	depMap := make(depsMapType)
	// configMap is used to avoid getting a remote config layer more than once
	configMap := make(map[string]*oci.ArtifactConfig)

	retrieveConfig := func(ref string) (*oci.ArtifactConfig, error) {
		config, ok := configMap[ref]
		if !ok {
			res, err := resolver(ref)
			if err != nil {
				return nil, err
			}

			configMap[ref] = &res.Config
			return &res.Config, nil
		}

		return config, nil
	}

	upsertMap := func(ref string) error {
		// fetch artifact config layer metadata
		config, err := retrieveConfig(ref)
		if err != nil {
			return err
		}

		if config.Version == "" {
			return fmt.Errorf("empty version for ref %q: config may be corrupted", ref)
		}

		ver, err := semver.Parse(config.Version)
		if err != nil {
			return fmt.Errorf("unable to parse version %q for ref %q, %w", config.Version, ref, err)
		}

		depMap[config.Name] = &depInfo{
			ref:    ref,
			config: config,
			ver:    &ver,
		}
		return nil
	}

	// Prepare initial map from user inputs
	for _, ref := range inRefs {
		config, err := retrieveConfig(ref)
		if err != nil {
			return nil, err
		}
		name := config.Name

		// todo: shall we shadow?
		if info, ok := depMap[name]; ok {
			return nil, fmt.Errorf(`cannot provide multiple references for %q: %q, %q`, name, info.ref, ref)
		}

		if err := upsertMap(ref); err != nil {
			return nil, err
		}
	}

	for {
		allOk := true
		// Since we are updating depMap in this for loop, let's copy the map for iterating it
		// while we continue inserting new values in the real depMap map.
		for name, info := range copyDepsMap(depMap) {
			if info.ok {
				continue
			}
			for _, required := range info.config.Dependencies {
				// Does already exist in the map?
				if existing, ok := depMap[required.Name]; ok {
					requiredVer, err := semver.Parse(required.Version)
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

					alternativeVer, err := semver.Parse(alternative.Version)
					if err != nil {
						return nil, fmt.Errorf(`invalid artifact config: version %q is not semver compatible`, required.Version)
					}

					// Is the alternative specified by the user compatible?
					if existing.ver.Major != alternativeVer.Major {
						return nil, fmt.Errorf(
							`%w: %s depends on %s:%s but an incompatible version %s:%s is required by other artifacts`,
							ErrCannotSatisfyDependencies, name, required.Name, required.Version, required.Name, existing.ver.String(),
						)
					}

					if alternativeVer.Compare(*existing.ver) > 0 {
						if err := upsertMap(alternative.Name + ":" + alternativeVer.String()); err != nil {
							return nil, err
						}
					}

					break
				}
				if foundAlternative {
					continue
				}

				// dep to be added or bumped
				if err := upsertMap(required.Name + ":" + required.Version); err != nil {
					return nil, err
				}
				allOk = false
			}

			// dep processed
			info.ok = true
		}

		if allOk {
			for _, info := range depMap {
				outRefs = append(outRefs, info.ref)
			}
			return
		}
	}
}
