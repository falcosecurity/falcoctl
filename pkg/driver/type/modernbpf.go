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
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"

	"github.com/falcosecurity/falcoctl/pkg/output"
)

// TypeModernBpf is the string for the bpf driver type.
const TypeModernBpf = "modern-bpf"

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

func (m *modernBpf) Load(_ *output.Printer, _ string, _ bool) error {
	return nil
}

func (m *modernBpf) Extension() string {
	return ""
}

func (m *modernBpf) HasArtifacts() bool {
	return false
}

//nolint:gocritic // the method shall not be able to modify kr
func (m *modernBpf) Build(_ context.Context, _ *output.Printer, _ kernelrelease.KernelRelease, _, _ string, _ map[string]string) (string, error) {
	return "", nil
}
