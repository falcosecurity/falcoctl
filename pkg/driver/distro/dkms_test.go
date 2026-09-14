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

//go:build linux

package driverdistro

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/stretchr/testify/require"
)

func TestVerifyDKMSInstallation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status string
		fail   bool
		wantOK bool
	}{
		{name: "installed", status: "falco/11.0.0+driver, 6.1.0, x86_64: installed\n", wantOK: true},
		{name: "only built", status: "falco/11.0.0+driver, 6.1.0, x86_64: built\n"},
		{name: "missing"},
		{name: "inconsistent", status: "falco/11.0.0+driver, 6.1.0, x86_64: installed (WARNING! Diff between built and installed module!)\n"},
		{name: "status command failed", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("FALCOCTL_TEST_DKMS_STATUS", tc.status)
			script := `#!/bin/sh
[ "$*" = 'status -m falco -v 11.0.0+driver -k 6.1.0 -a x86_64' ] || exit 2
printf '%s' "$FALCOCTL_TEST_DKMS_STATUS"
`
			if tc.fail {
				script += "exit 1\n"
			}
			require.NoError(t, os.WriteFile(filepath.Join(bin, "dkms"), []byte(script), 0o755))
			kr := kernelrelease.FromString("6.1.0")
			kr.Architecture = kernelrelease.ArchitectureAmd64
			err := verifyDKMSInstallation(context.Background(), "falco", "11.0.0+driver", kr)
			if tc.wantOK {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
