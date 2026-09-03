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

//go:build unix

package utils

import (
	"os"
	"os/user"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHomeDir is Unix-only: it relies on $HOME being the source of the home directory and on
// the user database fallback, while on Windows HomeDir simply returns os.UserHomeDir.
func TestHomeDir(t *testing.T) {
	t.Run("returns the home directory from the environment", func(t *testing.T) {
		want := t.TempDir()
		t.Setenv("HOME", want)

		assert.Equal(t, want, HomeDir())
	})

	t.Run("falls back to the user database when the environment is unset", func(t *testing.T) {
		t.Setenv("HOME", "")

		// Make sure the fallback path is actually exercised.
		_, err := os.UserHomeDir()
		require.Error(t, err)

		u, err := user.Current()
		if err != nil {
			// The user database is not available either (e.g. in minimal containers),
			// so there is nothing to fall back to.
			assert.Empty(t, HomeDir())
			return
		}
		assert.Equal(t, u.HomeDir, HomeDir())
	})
}
