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
	"fmt"

	"github.com/blang/semver"

	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/oci"
)

type artifactResolver func(ref string) (*oci.RegistryResult, error)
type depsMapType map[string]*depInfo

type depInfo struct {
	ref string
	res *oci.RegistryResult
	ver *semver.Version
	ok  bool
}

func copyDepsMap(in depsMapType) (out depsMapType) {
	out = make(depsMapType)
	for k, v := range in {
		out[k] = v
	}
	return
}

// ResolveDeps resolves dependencies to a list of references.
func ResolveDeps(resolver artifactResolver, inRefs ...string) (outRefs []string, err error) {
	depMap := make(depsMapType)
	upsertMap := func(name string, ref string) error {
		// fetch artifact metadata
		res, err := resolver(ref)
		if err != nil {
			return err
		}

		ver, err := semver.Parse(res.Config.Version)
		if err != nil {
			return err
		}

		depMap[name] = &depInfo{
			ref: ref,
			res: res,
			ver: &ver,
		}
		return nil
	}

	// Prepare initial map from user inputs
	for _, ref := range inRefs {
		name, err := utils.NameFromRef(ref)
		if err != nil {
			return nil, err
		}
		// todo: shall we shadow?
		if info, ok := depMap[name]; ok {
			return nil, fmt.Errorf(`cannot provide multiple references for %q: %q, %q`, name, info.ref, ref)
		}

		if err := upsertMap(name, ref); err != nil {
			return nil, err
		}
	}

	for {
		allOk := true
		for name, info := range copyDepsMap(depMap) {
			if info.ok {
				continue
			}
			for _, required := range info.res.Config.Dependencies {
				// Does already exist in the map?
				if existing, exists := depMap[required.Name]; exists {
					requiredVer, err := semver.Parse(required.Version)
					if err != nil {
						return nil, fmt.Errorf(`invalid artifact config: version %q is not semver compatible`, required.Version)
					}

					// Is the existing dep compatible?
					if existing.ver.Major != requiredVer.Major {
						return nil, fmt.Errorf(
							`cannot satisfy dependencies: %s depends on %s:%s but an incompatible version %s:%s is required by other artifacts`,
							name, required.Name, required.Version, required.Name, existing.ver.String(),
						)
					}

					// Is required version greater than existing one?
					if requiredVer.Compare(*existing.ver) <= 0 {
						continue
					}
				}

				// dep to be added or bumped
				if err := upsertMap(required.Name, required.Name+":"+required.Version); err != nil {
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
