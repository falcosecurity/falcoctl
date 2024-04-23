// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

func TestDistroGeneric(t *testing.T) {
	type testCase struct {
		krInput    string
		kvInput    string
		kvExpected string
	}
	testCases := []testCase{
		{
			krInput:    "4.19.283-3.ph3",
			kvInput:    "#1-photon SMP Fri Jun 16 02:25:27 UTC 2023",
			kvExpected: "1",
		},
		{
			krInput:    "6.7.2-arch1-2",
			kvInput:    "#1 SMP PREEMPT_DYNAMIC Wed, 31 Jan 2024 09:22:15 +0000",
			kvExpected: "1",
		},
		{
			krInput:    "6.7.2-arch1-2",
			kvInput:    "#231asfa #rf3f",
			kvExpected: "231",
		},
		{
			krInput:    "6.7.2-arch1-2",
			kvInput:    "#231asfa234",
			kvExpected: "231",
		},
	}

	g := &generic{}
	for _, tCase := range testCases {
		kr := kernelrelease.FromString(tCase.krInput)
		kr.KernelVersion = tCase.kvInput
		fixedKr := g.FixupKernel(kr)
		assert.Equal(t, tCase.kvExpected, fixedKr.KernelVersion)
	}
}
