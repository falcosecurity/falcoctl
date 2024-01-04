// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package follower

import (
	"os"
	"testing"

	"github.com/pterm/pterm"
	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

func TestCheckRequirements(t *testing.T) {
	printer := output.NewPrinter(pterm.LogLevelDebug, pterm.LogFormatterJSON, os.Stdout)

	type testArtifact struct {
		conf          *oci.ArtifactConfig
		falcoVersions map[string]string
		expectErr     bool
		testName      string
	}
	var testArtifactConfigs = []testArtifact{
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version_semver", Version: "0.26.0"}},
			},
			falcoVersions: map[string]string{"engine_version_semver": "0.26.0", "engine_version": "26"},
			expectErr:     false,
			testName:      "New Falco with new rules with new semver engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version_semver", Version: "26"}},
			},
			falcoVersions: map[string]string{"engine_version_semver": "0.26.0", "engine_version": "26"},
			expectErr:     true,
			testName:      "New Falco with new rules with old int engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version_semver", Version: "0.26.0"}},
			},
			falcoVersions: map[string]string{"engine_version": "26"},
			expectErr:     true,
			testName:      "Old Falco with new rules with new semver engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version_semver", Version: "26"}},
			},
			falcoVersions: map[string]string{"engine_version": "26"},
			expectErr:     true,
			testName:      "Old Falco with new new rules with old int engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version", Version: "26"}},
			},
			falcoVersions: map[string]string{"engine_version_semver": "0.26.0", "engine_version": "26"},
			expectErr:     false,
			testName:      "New Falco with old rules with old int engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version", Version: "0.26.0"}},
			},
			falcoVersions: map[string]string{"engine_version_semver": "0.26.0", "engine_version": "26"},
			expectErr:     true,
			testName:      "New Falco with old rules with new semver engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version", Version: "26"}},
			},
			falcoVersions: map[string]string{"engine_version": "26"},
			expectErr:     false,
			testName:      "Old Falco with old rules with old int engine version",
		},
		{
			conf: &oci.ArtifactConfig{
				Name:         "my_rule",
				Version:      "0.1.0",
				Requirements: []oci.ArtifactRequirement{{Name: "engine_version", Version: "0.26.0"}},
			},
			falcoVersions: map[string]string{"engine_version": "26"},
			expectErr:     true,
			testName:      "Old Falco with old rules with new semver engine version",
		},
	}

	for _, artConf := range testArtifactConfigs {
		t.Run(artConf.testName, func(t *testing.T) {
			config := Config{
				FalcoVersions: artConf.falcoVersions,
			}
			f, err := New("ghcr.io/falcosecurity/rules/my_rule:0.1.0", printer, &config)
			assert.NoError(t, err)

			err = f.checkRequirements(artConf.conf)
			if artConf.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
