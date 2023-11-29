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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDistroRhelCheck(t *testing.T) {
	const (
		etcPath         = "/etc/"
		releaseFilePath = etcPath + "redhat-release"
	)
	type testCase struct {
		hostRoot    string
		preFn       func() error
		postFn      func()
		retExpected bool
	}
	testCases := []testCase{
		{
			// No redhat-release file
			hostRoot: "/foo",
			preFn: func() error {
				return nil
			},
			postFn:      func() {},
			retExpected: false,
		},
		{
			// redhat-release file present under hostroot
			hostRoot: os.TempDir(),
			preFn: func() error {
				if err := os.MkdirAll(hostRoot+etcPath, 0o755); err != nil {
					return err
				}
				_, err := os.Create(hostRoot + releaseFilePath)
				return err
			},
			postFn: func() {
				_ = os.RemoveAll(hostRoot + releaseFilePath)
			},
			retExpected: true,
		},
		{
			// redhat-release file present but not under hostroot
			hostRoot: "/foo",
			preFn: func() error {
				if err := os.MkdirAll("."+etcPath, 0o755); err != nil {
					return err
				}
				_, err := os.Create("." + releaseFilePath)
				return err
			},
			postFn: func() {
				_ = os.RemoveAll("." + releaseFilePath)
			},
			retExpected: false,
		},
	}

	for _, tCase := range testCases {
		hostRoot = tCase.hostRoot
		r := &rhel{generic: &generic{}}
		err := tCase.preFn()
		require.NoError(t, err)
		assert.Equal(t, tCase.retExpected, r.check())
		tCase.postFn()
	}
}
