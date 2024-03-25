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
	"os/exec"
	"path/filepath"

	"github.com/docker/docker/pkg/homedir"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"
	"k8s.io/utils/mount"

	"github.com/falcosecurity/falcoctl/internal/utils"
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

//nolint:gocritic // the method shall not be able to modify kr
func (b *bpf) Build(ctx context.Context,
	printer *output.Printer,
	_ kernelrelease.KernelRelease,
	driverName, driverVersion string,
	env map[string]string,
) (string, error) {
	// We don't fail if this fails; let's try to build a probe anyway.
	_ = mountKernelDebug(printer)
	srcPath := fmt.Sprintf("/usr/src/%s-%s/bpf", driverName, driverVersion)

	makeCmdArgs := fmt.Sprintf(`make -C %q`, filepath.Clean(srcPath))
	makeCmd := exec.CommandContext(ctx, "bash", "-c", makeCmdArgs) //nolint:gosec // false positive
	// Append requested env variables to the command env
	makeCmd.Env = os.Environ()
	for key, val := range env {
		makeCmd.Env = append(makeCmd.Env, fmt.Sprintf("%s=%s", key, val))
	}
	out, err := makeCmd.CombinedOutput()
	if err != nil {
		printer.DefaultText.Print(string(out))
	}
	outProbe := fmt.Sprintf("%s/probe.o", srcPath)
	return outProbe, err
}

func mountKernelDebug(printer *output.Printer) error {
	// Mount /sys/kernel/debug that is needed on old (pre 4.17) kernel releases,
	// since these releases still did not support raw tracepoints.
	// BPF_PROG_TYPE_RAW_TRACEPOINT was introduced in 4.17 indeed:
	// https://github.com/torvalds/linux/commit/c4f6699dfcb8558d138fe838f741b2c10f416cf9
	exists, _ := utils.FileExists("/sys/kernel/debug/tracing")
	if exists {
		return nil
	}
	printer.Logger.Info("Mounting debugfs for bpf driver.")
	mounter := mount.New("/bin/mount")
	err := mounter.Mount("debugfs", "/sys/kernel/debug", "debugfs", []string{"nodev"})
	if err != nil {
		printer.Logger.Warn("Failed to mount debugfs.", printer.Logger.Args("err", err))
	}
	return err
}
