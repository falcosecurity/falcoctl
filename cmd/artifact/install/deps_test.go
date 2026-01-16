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
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				if ref == ref1 {
					return &oci.ArtifactConfig{
						Name:         "ref1",
						Version:      "0.1.2",
						Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.2.3"}},
					}, nil
				}

				splittedRef := strings.Split(ref, ":")
				return &oci.ArtifactConfig{
					Name:    splittedRef[0],
					Version: splittedRef[1],
					// no dependencies here
				}, nil
			}),
			expectedOutRef: []string{ref1, dep1},
			expectedErr:    nil,
		},
		{
			scenario:    "resolve common compatible dependency",
			description: "ref1:0.1.2 --> dep1:1.2.3, ref2:4.5.6 --> dep1:1.3.0",
			inRef:       []string{ref1, ref2},
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				switch ref {
				case ref1:
					return &oci.ArtifactConfig{
						Name:         "ref1",
						Version:      "0.1.2",
						Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.2.3"}},
					}, nil
				case ref2:
					return &oci.ArtifactConfig{
						Name:         "ref2",
						Version:      "4.5.6",
						Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.3.0"}},
					}, nil
				default:
					splittedRef := strings.Split(ref, ":")
					return &oci.ArtifactConfig{
						Name:    splittedRef[0],
						Version: splittedRef[1],
						// no dependencies here
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
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				switch ref {
				case ref1:
					return &oci.ArtifactConfig{
						Name:         "ref1",
						Version:      "0.1.2",
						Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "1.2.3"}},
					}, nil
				case ref2:
					return &oci.ArtifactConfig{
						Name:         "ref2",
						Version:      "4.5.6",
						Dependencies: []oci.ArtifactDependency{{Name: "dep1", Version: "2.3.0"}},
					}, nil
				default:
					splittedRef := strings.Split(ref, ":")
					return &oci.ArtifactConfig{
						Name:    splittedRef[0],
						Version: splittedRef[1],
						// no dependencies here
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
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				if ref == ref1 {
					return &oci.ArtifactConfig{
						Name:    "ref1",
						Version: "0.1.2",
						Dependencies: []oci.ArtifactDependency{
							{
								Name:         "dep1",
								Version:      "1.2.3",
								Alternatives: []oci.Dependency{{Name: "alt1", Version: "2.3.0"}},
							}},
					}, nil
				}
				splittedRef := strings.Split(ref, ":")
				return &oci.ArtifactConfig{
					Name:    splittedRef[0],
					Version: splittedRef[1],
					// no dependencies here
				}, nil
			}),
			expectedOutRef: []string{ref1, alt1},
			expectedErr:    ErrCannotSatisfyDependencies,
		},
		{
			scenario:    "resolve not compatible alternative",
			description: "ref1:0.1.2 --> dep1:1.2.3 | alt1:3.0.0",
			inRef:       []string{ref1, "alt1:3.0.0"},
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				if ref == ref1 {
					return &oci.ArtifactConfig{
						Name:    "ref1",
						Version: "0.1.2",
						Dependencies: []oci.ArtifactDependency{
							{
								Name:         "dep1",
								Version:      "1.2.3",
								Alternatives: []oci.Dependency{{Name: "alt1", Version: "2.3.0"}},
							}},
					}, nil
				}

				splittedRef := strings.Split(ref, ":")
				return &oci.ArtifactConfig{
					Name:    splittedRef[0],
					Version: splittedRef[1],
					// no dependencies here
				}, nil
			}),
			expectedOutRef: nil,
			expectedErr:    ErrCannotSatisfyDependencies,
		},
		{
			scenario:    "tolerant semver - major only version",
			description: "custom-rules:1 (major only) should work",
			inRef:       []string{"ghcr.io/example/falco-test/custom-rules:1"},
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				return &oci.ArtifactConfig{
					Name:    "custom-rules",
					Version: "1",
				}, nil
			}),
			expectedOutRef: []string{"ghcr.io/example/falco-test/custom-rules:1"},
			expectedErr:    nil,
		},
		{
			scenario:    "tolerant semver - major.minor version",
			description: "custom-rules:1.2 (major.minor) should work",
			inRef:       []string{"ghcr.io/example/rules:1.2"},
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				return &oci.ArtifactConfig{
					Name:    "rules",
					Version: "1.2", // Major.Minor only - should be parsed as 1.2.0
				}, nil
			}),
			expectedOutRef: []string{"ghcr.io/example/rules:1.2"},
			expectedErr:    nil,
		},
		{
			scenario:    "tolerant semver - version with v prefix",
			description: "custom-rules:v1.2.3 (v prefix) should work",
			inRef:       []string{"ghcr.io/example/rules:v1.2.3"},
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				return &oci.ArtifactConfig{
					Name:    "rules",
					Version: "v1.2.3", // v prefix - should be parsed as 1.2.3
				}, nil
			}),
			expectedOutRef: []string{"ghcr.io/example/rules:v1.2.3"},
			expectedErr:    nil,
		},
		{
			scenario:    "tolerant semver - dependency with major only version",
			description: "ref:0.1.2 --> dep:1 (major only dependency)",
			inRef:       []string{"ghcr.io/example/ref:0.1.2"},
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				if ref == "ghcr.io/example/ref:0.1.2" {
					return &oci.ArtifactConfig{
						Name:         "ref",
						Version:      "0.1.2",
						Dependencies: []oci.ArtifactDependency{{Name: "dep", Version: "1"}}, // Major only
					}, nil
				}
				return &oci.ArtifactConfig{
					Name:    "dep",
					Version: "1", // Major only
				}, nil
			}),
			expectedOutRef: []string{"ghcr.io/example/ref:0.1.2", "dep:1"},
			expectedErr:    nil,
		},
		{
			scenario:    "tolerant semver - compatible major versions with tolerant format",
			description: "ref1:1 --> dep:1, ref2:2 --> dep:1.5 (compatible majors with tolerant)",
			inRef:       []string{"ref1:1", "ref2:2"},
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				switch ref {
				case "ref1:1":
					return &oci.ArtifactConfig{
						Name:         "ref1",
						Version:      "1", // Major only
						Dependencies: []oci.ArtifactDependency{{Name: "dep", Version: "1"}},
					}, nil
				case "ref2:2":
					return &oci.ArtifactConfig{
						Name:         "ref2",
						Version:      "2", // Major only
						Dependencies: []oci.ArtifactDependency{{Name: "dep", Version: "1.5"}},
					}, nil
				default:
					splittedRef := strings.Split(ref, ":")
					return &oci.ArtifactConfig{
						Name:    splittedRef[0],
						Version: splittedRef[1],
					}, nil
				}
			}),
			expectedOutRef: []string{"ref1:1", "ref2:2", "dep:1.5"},
			expectedErr:    nil,
		},
		{
			scenario:    "tolerant semver - incompatible major versions with tolerant format",
			description: "ref1:1 --> dep:1, ref2:2 --> dep:2 (incompatible majors with tolerant)",
			inRef:       []string{"ref1:1", "ref2:2"},
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				switch ref {
				case "ref1:1":
					return &oci.ArtifactConfig{
						Name:         "ref1",
						Version:      "1",
						Dependencies: []oci.ArtifactDependency{{Name: "dep", Version: "1"}}, // Major 1
					}, nil
				case "ref2:2":
					return &oci.ArtifactConfig{
						Name:         "ref2",
						Version:      "2",
						Dependencies: []oci.ArtifactDependency{{Name: "dep", Version: "2"}}, // Major 2
					}, nil
				default:
					splittedRef := strings.Split(ref, ":")
					return &oci.ArtifactConfig{
						Name:    splittedRef[0],
						Version: splittedRef[1],
					}, nil
				}
			}),
			expectedOutRef: nil,
			expectedErr:    ErrCannotSatisfyDependencies,
		},
		{
			scenario:    "tolerant semver - alternative with major only version",
			description: "ref:1 --> dep:1 | alt:2 (alternative with tolerant)",
			inRef:       []string{"ref:1", "alt:2"},
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				if ref == "ref:1" {
					return &oci.ArtifactConfig{
						Name:    "ref",
						Version: "1",
						Dependencies: []oci.ArtifactDependency{
							{
								Name:         "dep",
								Version:      "1",
								Alternatives: []oci.Dependency{{Name: "alt", Version: "2"}},
							}},
					}, nil
				}
				splittedRef := strings.Split(ref, ":")
				return &oci.ArtifactConfig{
					Name:    splittedRef[0],
					Version: splittedRef[1],
				}, nil
			}),
			expectedOutRef: []string{"ref:1", "alt:2"},
			expectedErr:    ErrCannotSatisfyDependencies,
		},
		{
			scenario:    "tolerant semver - version zero",
			description: "rules:0 (version zero) should work for pre-1.0 software",
			inRef:       []string{"ghcr.io/example/rules:0"},
			configResolver: artifactConfigResolver(func(ref string) (*oci.ArtifactConfig, error) {
				return &oci.ArtifactConfig{
					Name:    "rules",
					Version: "0",
				}, nil
			}),
			expectedOutRef: []string{"ghcr.io/example/rules:0"},
			expectedErr:    nil,
		},
	}

	for _, testCase := range testCases {
		artifacts, err := ResolveDeps(testCase.configResolver, refResolver, testCase.inRef...)
		if err != nil && !errors.Is(err, testCase.expectedErr) {
			t.Fatalf("unexpected error in scenario %q, %q: %v",
				testCase.scenario, testCase.description, err)
		}

		outRef := make([]string, 0, len(artifacts))
		for _, info := range artifacts {
			outRef = append(outRef, info.ref)
		}

		if !testCase.checkOutRef(outRef) {
			t.Fatalf("dependencies not correctly resolved in scenario %q, %q:\n got %v, expected %v",
				testCase.scenario, testCase.description, outRef, testCase.expectedOutRef)
		}
	}
}
