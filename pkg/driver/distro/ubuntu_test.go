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
	"testing"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/stretchr/testify/assert"
)

func TestDistroUbuntuInitFixup(t *testing.T) {
	type testCase struct {
		krInput        string
		kvInput        string
		flavorExpected string
		kvExpected     string
	}
	testCases := []testCase{
		{
			krInput:        "5.0.0-1028-aws-5.0",
			kvInput:        "#26~22.04.1-Ubuntu SMP Mon Apr 24 01:58:15 UTC 2023",
			flavorExpected: "ubuntu-aws",
			kvExpected:     "26~22.04.1",
		},
		{
			krInput:        "5.0.0-1028-aws-5.0",
			kvInput:        "#26",
			flavorExpected: "ubuntu-aws",
			kvExpected:     "26",
		},
		{
			krInput:        "5.0.0-1028-aws-5.0",
			kvInput:        "#26-Ubuntu",
			flavorExpected: "ubuntu-aws",
			kvExpected:     "26",
		},
		{
			krInput:        "5.0.0",
			kvInput:        "#26",
			flavorExpected: "ubuntu-generic",
			kvExpected:     "26",
		},
		{
			krInput:        "6.5.0-9-lowlatency",
			kvInput:        "#9.1",
			flavorExpected: "ubuntu-lowlatency",
			kvExpected:     "9.1",
		},
		{
			krInput:        "6.5.0-1008-gcp",
			kvInput:        "#8",
			flavorExpected: "ubuntu-gcp",
			kvExpected:     "8",
		},
		{
			krInput:        "6.5.0-1008-aws",
			kvInput:        "#8~22.04.1",
			flavorExpected: "ubuntu-aws",
			kvExpected:     "8~22.04.1",
		},
	}

	for _, tCase := range testCases {
		ub := &ubuntu{generic: &generic{}}
		kr := kernelrelease.FromString(tCase.krInput)
		kr.KernelVersion = tCase.kvInput
		err := ub.init(kr, "", nil)
		assert.NoError(t, err)
		assert.Equal(t, tCase.flavorExpected, ub.String())
		fixedKr := ub.FixupKernel(kr)
		assert.Equal(t, tCase.kvExpected, fixedKr.KernelVersion)
	}
}
