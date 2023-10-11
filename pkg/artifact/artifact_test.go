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
