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
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/falcosecurity/falcoctl/pkg/oci"
)

type testCase struct {
	scenario       string
	description    string
	inRef          []string
	resolver       artifactConfigResolver
	expectedOutRef []string
	expectedErr    error
}

func (t *testCase) checkOutRef(outRef []string) bool {
	if len(t.expectedOutRef) != len(outRef) {
		return false
	}

	sort.Strings(outRef)
	sort.Strings(t.expectedOutRef)

	for i, val := range t.expectedOutRef {
		if val != outRef[i] {
			return false
		}
	}

	return true
}

func TestResolveDeps(t *testing.T) {
	testCases := []testCase{
		{
			scenario:    "resolve one dependency",
			description: "ref:0.1.2 --> dep1:1.2.3",
			inRef:       []string{"ref:0.1.2"},
			resolver: artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
				if ref == "ref:0.1.2" {
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:         "ref",
							Version:      "0.1.2",
							Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.2.3"}},
						},
					}, nil
				} else {
					splittedRef := strings.Split(ref, ":")
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:    splittedRef[0],
							Version: splittedRef[1],
							// no dependencies here
						},
					}, nil
				}
			}),
			expectedOutRef: []string{"ref:0.1.2", "dep1:1.2.3"},
			expectedErr:    nil,
		},
		{
			scenario:    "resolve common compatible dependency",
			description: "ref1:0.1.2 --> dep1:1.2.3, ref2:4.5.6 --> dep1:1.3.0",
			inRef:       []string{"ref1:0.1.2", "ref2:4.5.6"},
			resolver: artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
				if ref == "ref:0.1.2" {
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:         "ref1",
							Version:      "0.1.2",
							Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.2.3"}},
						},
					}, nil
				} else if ref == "ref2:4.5.6" {
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:         "ref2",
							Version:      "4.5.6",
							Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.3.0"}},
						},
					}, nil
				} else {
					splittedRef := strings.Split(ref, ":")
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:    splittedRef[0],
							Version: splittedRef[1],
							// no dependencies here
						},
					}, nil
				}
			}),
			expectedOutRef: []string{"ref1:0.1.2", "ref2:4.5.6", "dep1:1.3.0"},
			expectedErr:    nil,
		},
		{
			scenario:    "resolve common but not compatible dependency",
			description: "ref1:0.1.2 --> dep1:1.2.3, ref2:4.5.6 --> dep1:2.3.0",
			inRef:       []string{"ref1:0.1.2", "ref2:4.5.6"},
			resolver: artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
				if ref == "ref1:0.1.2" {
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:         "ref1",
							Version:      "0.1.2",
							Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.2.3"}},
						},
					}, nil
				} else if ref == "ref2:4.5.6" {
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:         "ref2",
							Version:      "4.5.6",
							Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "2.3.0"}},
						},
					}, nil
				} else {
					splittedRef := strings.Split(ref, ":")
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:    splittedRef[0],
							Version: splittedRef[1],
							// no dependencies here
						},
					}, nil
				}
			}),
			expectedOutRef: nil,
			expectedErr:    CannotSatisfyDependenciesErr,
		},
		{
			scenario:    "resolve compatible alternative",
			description: "ref1:0.1.2 --> dep1:1.2.3 | alt1:2.5.0",
			inRef:       []string{"ref1:0.1.2", "alt1:2.5.0"},
			resolver: artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
				if ref == "ref1:0.1.2" {
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:    "ref1",
							Version: "0.1.2",
							Dependencies: []oci.ArtifactDependency{
								{
									Name:         "dep1",
									Version:      "1.2.3",
									Alternatives: []oci.Dependency{{Name: "alt1", Version: "2.3.0"}},
								}},
						},
					}, nil
				} else {
					splittedRef := strings.Split(ref, ":")
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:    splittedRef[0],
							Version: splittedRef[1],
							// no dependencies here
						},
					}, nil
				}
			}),
			expectedOutRef: []string{"ref1:0.1.2", "alt1:2.5.0"},
			expectedErr:    CannotSatisfyDependenciesErr,
		},
		{
			scenario:    "resolve not compatible alternative",
			description: "ref1:0.1.2 --> dep1:1.2.3 | alt1:3.0.0",
			inRef:       []string{"ref1:0.1.2", "alt1:3.0.0"},
			resolver: artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
				if ref == "ref1:0.1.2" {
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:    "ref1",
							Version: "0.1.2",
							Dependencies: []oci.ArtifactDependency{
								{
									Name:         "dep1",
									Version:      "1.2.3",
									Alternatives: []oci.Dependency{{Name: "alt1", Version: "2.3.0"}},
								}},
						},
					}, nil
				} else {
					splittedRef := strings.Split(ref, ":")
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:    splittedRef[0],
							Version: splittedRef[1],
							// no dependencies here
						},
					}, nil
				}
			}),
			expectedOutRef: nil,
			expectedErr:    CannotSatisfyDependenciesErr,
		},
	}

	for _, testCase := range testCases {
		outRef, err := ResolveDeps(testCase.resolver, testCase.inRef...)
		if err != nil && !errors.Is(err, testCase.expectedErr) {
			t.Fatalf("unexpected error in scenario %q, %q: %v",
				testCase.scenario, testCase.description, err)
		}

		if !testCase.checkOutRef(outRef) {
			t.Fatalf("dependencies not correctly resolved in scenario %q, %q:\n got %v, expected %v",
				testCase.scenario, testCase.description, outRef, testCase.expectedOutRef)
		}
	}

}
