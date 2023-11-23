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

package driverdistro

import (
	"os"
	"testing"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDistroDebianCheck(t *testing.T) {
	type testCase struct {
		hostRoot    string
		preFn       func() error
		postFn      func()
		retExpected bool
	}
	testCases := []testCase{
		{
			// No debian_version file
			hostRoot: "/foo",
			preFn: func() error {
				return nil
			},
			postFn:      func() {},
			retExpected: false,
		},
		{
			// debian_version file present under hostroot
			hostRoot: ".",
			preFn: func() error {
				if err := os.MkdirAll("./etc/", 0o755); err != nil {
					return err
				}
				_, err := os.Create("./etc/debian_version")
				return err
			},
			postFn: func() {
				_ = os.RemoveAll("./etc/debian_version")
			},
			retExpected: true,
		},
		{
			// debian_version file present but not under hostroot
			hostRoot: "/foo",
			preFn: func() error {
				if err := os.MkdirAll("./etc/", 0o755); err != nil {
					return err
				}
				_, err := os.Create("./etc/debian_version")
				return err
			},
			postFn: func() {
				_ = os.RemoveAll("./etc/debian_version")
			},
			retExpected: false,
		},
	}

	for _, tCase := range testCases {
		deb := &debian{generic: &generic{}}
		err := tCase.preFn()
		require.NoError(t, err)
		assert.Equal(t, tCase.retExpected, deb.check(tCase.hostRoot))
		tCase.postFn()
	}
}

func TestDistroDebianFixup(t *testing.T) {
	type testCase struct {
		krInput    string
		kvInput    string
		krExpected string
	}
	testCases := []testCase{
		{
			// Substitution needed since kernelversion contains the real kernelrelease
			krInput:    "5.10.0-0.deb10.22-rt-amd64",
			kvInput:    "5.10.178-3",
			krExpected: "5.10.178-3-rt-amd64",
		},
		{
			// Substitution needed since kernelversion contains the real kernelrelease
			krInput:    "5.10.0-0.deb10.22-amd64",
			kvInput:    "5.10.178-3",
			krExpected: "5.10.178-3-amd64",
		},
		{
			// Substitution NOT needed
			krInput:    "5.10.0-0.deb10.22-amd64",
			kvInput:    "1",
			krExpected: "5.10.0-0.deb10.22-amd64",
		},
		{
			// Substitution NOT needed
			krInput:    "5.10.0-0",
			kvInput:    "1",
			krExpected: "5.10.0-0",
		},
		{
			// Substitution NOT needed
			krInput:    "6.5.3-1~bpo12+1-rt-amd64",
			kvInput:    "1",
			krExpected: "6.5.3-1~bpo12+1-rt-amd64",
		},
	}
	for _, tCase := range testCases {
		deb := &debian{generic: &generic{}}
		kr := kernelrelease.FromString(tCase.krInput)
		kr.KernelVersion = tCase.kvInput
		fixedKr := deb.FixupKernel(kr)
		assert.Equal(t, tCase.krExpected, fixedKr.String())
	}
}
