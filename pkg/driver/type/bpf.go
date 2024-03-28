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
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/docker/pkg/homedir"
	"github.com/falcosecurity/driverkit/cmd"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"

	"github.com/falcosecurity/falcoctl/pkg/output"
)

// TypeBpf is the string for the bpf driver type.
const TypeBpf = "ebpf"

func init() {
	driverTypes[TypeBpf] = &bpf{}
}

type bpf struct{}

func (b *bpf) String() string {
	return TypeBpf
}

func (b *bpf) Cleanup(printer *output.Printer, driverName string) error {
	symlinkPath := filepath.Join(homedir.Get(), ".falco", fmt.Sprintf("%s-bpf.o", driverName))
	printer.Logger.Info("Removing eBPF probe symlink", printer.Logger.Args("path", symlinkPath))
	_ = os.Remove(symlinkPath)
	return nil
}

func (b *bpf) Load(printer *output.Printer, src, driverName string, fallback bool) error {
	if !fallback {
		symlinkPath := filepath.Join(homedir.Get(), ".falco", fmt.Sprintf("%s-bpf.o", driverName))
		printer.Logger.Info("Symlinking eBPF probe", printer.Logger.Args("src", src, "dest", symlinkPath))
		err := os.Symlink(src, symlinkPath)
		if err == nil {
			printer.Logger.Info("eBPF probe symlinked")
		} else {
			printer.Logger.Info("Failed to symlink eBPF probe")
		}
		return err
	}
	return nil
}

func (b *bpf) Extension() string {
	return ".o"
}

func (b *bpf) HasArtifacts() bool {
	return true
}

//nolint:gocritic // the method shall not be able to modify kr
func (b *bpf) Supported(kr kernelrelease.KernelRelease) bool {
	return kr.SupportsProbe()
}

func (b *bpf) ToOutput(destPath string) cmd.OutputOptions {
	return cmd.OutputOptions{
		Probe: destPath,
	}
}
