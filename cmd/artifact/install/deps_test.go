// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
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
	configResolver artifactConfigResolver
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
	const (
		ref1           = "ref1:0.1.2"
		ref2           = "ref2:4.5.6"
		dep1           = "dep1:1.2.3"
		dep1Compatible = "dep1:1.3.0"
		alt1           = "alt1:2.5.0"
	)

	refResolver := refResolver(func(ref string) (string, error) {
		return ref, nil
	})

	testCases := []testCase{
		{
			scenario:    "resolve one dependency",
			description: "ref:0.1.2 --> dep1:1.2.3",
			inRef:       []string{ref1},
			configResolver: artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
				if ref == ref1 {
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:         "ref1",
							Version:      "0.1.2",
							Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.2.3"}},
						},
					}, nil
				}

				splittedRef := strings.Split(ref, ":")
				return &oci.RegistryResult{
					Config: oci.ArtifactConfig{
						Name:    splittedRef[0],
						Version: splittedRef[1],
						// no dependencies here
					},
				}, nil
			}),
			expectedOutRef: []string{ref1, dep1},
			expectedErr:    nil,
		},
		{
			scenario:    "resolve common compatible dependency",
			description: "ref1:0.1.2 --> dep1:1.2.3, ref2:4.5.6 --> dep1:1.3.0",
			inRef:       []string{ref1, ref2},
			configResolver: artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
				switch ref {
				case ref1:
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:         "ref1",
							Version:      "0.1.2",
							Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.2.3"}},
						},
					}, nil
				case ref2:
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:         "ref2",
							Version:      "4.5.6",
							Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.3.0"}},
						},
					}, nil
				default:
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
			expectedOutRef: []string{ref1, ref2, dep1Compatible},
			expectedErr:    nil,
		},
		{
			scenario:    "resolve common but not compatible dependency",
			description: "ref1:0.1.2 --> dep1:1.2.3, ref2:4.5.6 --> dep1:2.3.0",
			inRef:       []string{ref1, ref2},
			configResolver: artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
				switch ref {
				case ref1:
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:         "ref1",
							Version:      "0.1.2",
							Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.2.3"}},
						},
					}, nil
				case ref2:
					return &oci.RegistryResult{
						Config: oci.ArtifactConfig{
							Name:         "ref2",
							Version:      "4.5.6",
							Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "2.3.0"}},
						},
					}, nil
				default:
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
			expectedErr:    ErrCannotSatisfyDependencies,
		},
		{
			scenario:    "resolve compatible alternative",
			description: "ref1:0.1.2 --> dep1:1.2.3 | alt1:2.5.0",
			inRef:       []string{ref1, alt1},
			configResolver: artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
				if ref == ref1 {
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
				}
				splittedRef := strings.Split(ref, ":")
				return &oci.RegistryResult{
					Config: oci.ArtifactConfig{
						Name:    splittedRef[0],
						Version: splittedRef[1],
						// no dependencies here
					},
				}, nil
			}),
			expectedOutRef: []string{ref1, alt1},
			expectedErr:    ErrCannotSatisfyDependencies,
		},
		{
			scenario:    "resolve not compatible alternative",
			description: "ref1:0.1.2 --> dep1:1.2.3 | alt1:3.0.0",
			inRef:       []string{ref1, "alt1:3.0.0"},
			configResolver: artifactConfigResolver(func(ref string) (*oci.RegistryResult, error) {
				if ref == ref1 {
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
				}

				splittedRef := strings.Split(ref, ":")
				return &oci.RegistryResult{
					Config: oci.ArtifactConfig{
						Name:    splittedRef[0],
						Version: splittedRef[1],
						// no dependencies here
					},
				}, nil
			}),
			expectedOutRef: nil,
			expectedErr:    ErrCannotSatisfyDependencies,
		},
	}

	for _, testCase := range testCases {
		outRef, err := ResolveDeps(testCase.configResolver, refResolver, testCase.inRef...)
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
