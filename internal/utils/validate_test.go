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

package utils

import "testing"

func TestNameFromRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		want    string
		wantErr bool
	}{
		{"reg_repo_tag", "ghcr.io/falcosecurity/rules/my_rule:0.1.0", "my_rule", false},
		{"reg_repo_hash",
			"ghcr.io/falcosecurity/rules/my_rule@sha256:67df5990affad0d8f0b13c6e611733f3b5725029135368207ed0e4d58341b5d7",
			"my_rule", false},
		{"reg_repo_tag_hash",
			"ghcr.io/falcosecurity/rules/my_rule:0.1.0@sha256:67df5990affad0d8f0b13c6e611733f3b5725029135368207ed0e4d58341b5d7",
			"my_rule", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NameFromRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("NameFromRef() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NameFromRef() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRepositoryFromRef(t *testing.T) {
	tests := []struct {
		name    string
		ref     string
		want    string
		wantErr bool
	}{
		{"reg_repo_tag", "ghcr.io/falcosecurity/rules/my_rule:0.1.0", "ghcr.io/falcosecurity/rules/my_rule", false},
		{"reg_repo_hash",
			"ghcr.io/falcosecurity/rules/my_rule@sha256:67df5990affad0d8f0b13c6e611733f3b5725029135368207ed0e4d58341b5d7",
			"ghcr.io/falcosecurity/rules/my_rule", false},
		{"reg_repo_tag_hash",
			"ghcr.io/falcosecurity/rules/my_rule:0.1.0@sha256:67df5990affad0d8f0b13c6e611733f3b5725029135368207ed0e4d58341b5d7",
			"ghcr.io/falcosecurity/rules/my_rule", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RepositoryFromRef(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("RepositoryFromRef() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("RepositoryFromRef() got = %v, want %v", got, tt.want)
			}
		})
	}
}
