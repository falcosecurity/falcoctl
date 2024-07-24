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

package drivertype

import (
	_ "unsafe" // Needed for go:linkname to be able to access a private function from cilium/ebpf/features.

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/falcosecurity/driverkit/cmd"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"

	"github.com/falcosecurity/falcoctl/pkg/output"
)

// TypeModernBpf is the string for the bpf driver type.
const TypeModernBpf = "modern_ebpf"

func init() {
	driverTypes[TypeModernBpf] = &modernBpf{}
}

type modernBpf struct{}

func (m *modernBpf) String() string {
	return TypeModernBpf
}

func (m *modernBpf) Cleanup(_ *output.Printer, _ string) error {
	return nil
}

func (m *modernBpf) Load(_ *output.Printer, _, _ string, _ bool) error {
	return nil
}

func (m *modernBpf) Extension() string {
	return ""
}

func (m *modernBpf) HasArtifacts() bool {
	return false
}

// Get the private symbol `probeProgram` that will be used to test for
// type Tracing, attachType AttachTraceRawTp program availability.
//
//go:linkname probeProgram github.com/cilium/ebpf/features.probeProgram
func probeProgram(spec *ebpf.ProgramSpec) error

//nolint:gocritic // the method shall not be able to modify kr
func (m *modernBpf) Supported(_ kernelrelease.KernelRelease) bool {
	// We can't directly use this because it uses the wrong attachtype.
	// err := features.HaveProgramType(ebpf.Tracing)
	// Therefore, we need to manually build a feature test.
	// Empty tracing program that just returns 0
	progSpec := &ebpf.ProgramSpec{
		Type:       ebpf.Tracing,
		AttachType: ebpf.AttachTraceRawTp,
		AttachTo:   "sys_enter",
	}
	err := probeProgram(progSpec)
	if err != nil {
		return false
	}

	return features.HaveMapType(ebpf.RingBuf) == nil
}

func (m *modernBpf) ToOutput(_ string) cmd.OutputOptions {
	return cmd.OutputOptions{}
}
