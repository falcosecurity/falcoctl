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

func TestDistroMinikubeInitFixup(t *testing.T) {
	type testCase struct {
		hostRoot    string
		preFn       func() error
		postFn      func()
		retExpected bool
		kvExpected  string
	}
	testCases := []testCase{
		{
			// No VERSION file
			hostRoot: "/foo",
			preFn: func() error {
				return nil
			},
			postFn:      func() {},
			retExpected: false,
		},
		{
			// VERSION file present under hostroot
			hostRoot: ".",
			preFn: func() error {
				if err := os.MkdirAll("./etc/", 0o755); err != nil {
					return err
				}
				return os.WriteFile("./etc/VERSION", []byte("v1.26.0-1655407986-14197"), os.ModePerm)
			},
			postFn: func() {
				_ = os.RemoveAll("./etc/VERSION")
			},
			retExpected: true,
			kvExpected:  "1_1.26.0",
		},
		{
			// VERSION file present but not under hostroot
			hostRoot: "/foo",
			preFn: func() error {
				if err := os.MkdirAll("./etc/", 0o755); err != nil {
					return err
				}
				return os.WriteFile("./etc/VERSION", []byte("v1.26.0-1655407986-14197"), os.ModePerm)
			},
			postFn: func() {
				_ = os.RemoveAll("./etc/VERSION")
			},
			retExpected: false,
		},
	}

	for _, tCase := range testCases {
		mn := &minikube{generic: &generic{}}
		err := tCase.preFn()
		require.NoError(t, err)
		assert.Equal(t, tCase.retExpected, mn.check(tCase.hostRoot))
		if tCase.retExpected {
			kr := kernelrelease.KernelRelease{}
			fixedKr := mn.FixupKernel(kr)
			assert.Equal(t, tCase.kvExpected, fixedKr.KernelVersion)
		}
		tCase.postFn()
	}
}
