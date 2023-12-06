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
	"os/exec"
	"path/filepath"

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

func (b *bpf) Cleanup(printer *output.Printer, _ string) error {
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
	// We don't fail if this fails; let's try to build a probe anyway.
	if err := mounter.Mount("debugfs", "/sys/kernel/debug", "debugfs", []string{"nodev"}); err != nil {
		printer.Logger.Warn("Failed to mount debugfs.", printer.Logger.Args("err", err))
	}
	return nil
}

func (b *bpf) Load(_ *output.Printer, _ string, _ bool) error {
	return nil
}

func (b *bpf) Extension() string {
	return ".o"
}

func (b *bpf) HasArtifacts() bool {
	return true
}

//nolint:gocritic // the method shall not be able to modify kr
func (b *bpf) Build(ctx context.Context,
	printer *output.Printer,
	_ kernelrelease.KernelRelease,
	driverName, driverVersion string,
	env map[string]string,
) (string, error) {
	srcPath := fmt.Sprintf("/usr/src/%s-%s/bpf", driverName, driverVersion)

	makeCmdArgs := fmt.Sprintf(`make -C %q`, filepath.Clean(srcPath))
	makeCmd := exec.CommandContext(ctx, "bash", "-c", makeCmdArgs) //nolint:gosec // false positive
	// Append requested env variables to the command env
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
