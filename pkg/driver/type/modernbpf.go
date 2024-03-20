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

package drivertype

import (
	"fmt"
	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"
	"os/exec"

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

//nolint:gocritic // the method shall not be able to modify kr
func (m *modernBpf) Supported(kr kernelrelease.KernelRelease) bool {
	bpftool, err := exec.LookPath("bpftool")
	if err != nil {
		// We should be pretty sure that modern bpf will work on kernels >= 5.8.0
		return kr.GTE(semver.MustParse("5.8.0"))
	}
	// Test with bpftool that the kernel exposes the features we need.
	// Note that this is not 100% guarantee to work in all cases since
	// "program_type tracing" might pass even if the exactly program we need is not supported.
	// TODO: test with https://github.com/cilium/ebpf
	bpftoolCmd := fmt.Sprintf(`%s feature probe kernel | grep -q `+
		`-e "map_type ringbuf is available" `+
		`-e "program_type tracing is available"`, bpftool)

	_, err = exec.Command("bash", "-c", bpftoolCmd).CombinedOutput()
	return err == nil
}

//nolint:gocritic // the method shall not be able to modify kr
func (m *modernBpf) Build(_ context.Context, _ *output.Printer, _ kernelrelease.KernelRelease, _, _ string, _ map[string]string) (string, error) {
	return "", nil
}
