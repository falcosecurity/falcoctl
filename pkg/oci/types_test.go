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

import "testing"

func TestParseDepedencies(t *testing.T) {
	ac := ArtifactConfig{}

	err := ac.ParseDependencies(
		"my-artifact:1.0.0-pre3",
		"default-artifact:1.0.0|alternative2:1.0.1|alternative1:1.0.2-rc1",
	)

	if err != nil {
		t.Error(err)
	}

	// deps must be sorted now
	if ac.Dependencies[0].Name != "default-artifact" {
		t.Fatal("first dep name does not match, got:", ac.Dependencies[0])
	}

	if ac.Dependencies[0].Version != "1.0.0" {
		t.Fatal("first dep version does not match, got:", ac.Dependencies[0])
	}

	if len(ac.Dependencies[0].Alternatives) != 2 {
		t.Fatal("first dep should not have exactly 2 alternatives, got:", ac.Dependencies[0])
	}

	if len(ac.Dependencies[1].Alternatives) != 0 {
		t.Fatal("second dep should have no alternatives, got:", ac.Dependencies[1])
	}
}
