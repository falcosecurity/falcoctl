// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 The Falco Authors
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

package artifact

import (
	"errors"
	"testing"
)

func TestValidateVersion(t *testing.T) {
	// ValidateVersion enforces strict semver format (used on push).
	// This is intentionally stricter than ParseTolerant (used on install).
	tests := []struct {
		version string
		valid   bool
		reason  string
	}{
		// Valid formats (full semver only)
		{"1.0.0", true, "full semver"},
		{"0.1.0", true, "full semver with major 0"},
		{"2.3.4", true, "full semver"},
		{"1.0.0-rc1", true, "full semver with pre-release"},
		{"1.2.3-alpha.1", true, "full semver with pre-release"},

		// Invalid formats (rejected on push, but accepted by ParseTolerant on install)
		{"1", false, "major-only not allowed"},
		{"1.0", false, "major.minor not allowed"},
		{"v1.0.0", false, "v-prefix not allowed"},
		{"v1", false, "v-prefix with major-only not allowed"},
		{"1.0.0.0", false, "too many version components"},
		{"invalid", false, "non-numeric version"},
	}

	for _, tt := range tests {
		err := ValidateVersion(tt.version)
		if tt.valid && err != nil {
			t.Errorf("ValidateVersion(%q) = %v, want nil (%s)", tt.version, err, tt.reason)
		}
		if !tt.valid && err == nil {
			t.Errorf("ValidateVersion(%q) = nil, want error (%s)", tt.version, tt.reason)
		}
		if !tt.valid && err != nil && !errors.Is(err, ErrInvalidVersion) {
			t.Errorf("ValidateVersion(%q) error = %v, want ErrInvalidVersion", tt.version, err)
		}
	}
}

func TestParseRef(t *testing.T) {
	a, err := ParseRef("my-plugin:1.2.3")
	if err != nil {
		t.Error(err)
	}
	if a == nil || a.Name != "my-plugin" || a.Version != "1.2.3" {
		t.Fatal("invalid Artifact:", a)
	}

	_, err = ParseRef("invalid ref")
	if !errors.Is(err, ErrInvalidRef) {
		t.Fatal("invalid ref error not matched")
	}

	_, err = ParseRef("iNvAlId NaMe:1.2.3")
	if !errors.Is(err, ErrInvalidName) {
		t.Fatal("invalid name error not matched")
	}

	_, err = ParseRef("my-plugin:invalid-version")
	if !errors.Is(err, ErrInvalidVersion) {
		t.Fatal("invalid version error not matched")
	}
}
