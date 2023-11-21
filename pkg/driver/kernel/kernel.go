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

// Package driverkernel implements the kernel info fetching helpers.
package driverkernel

import (
	"bytes"
	"runtime"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/sys/unix"
)

// FetchInfo returns information about currently running kernel.
func FetchInfo(enforcedKR, enforcedKV string) (kernelrelease.KernelRelease, error) {
	var (
		kv string
		kr string
	)
	if enforcedKR == "" || enforcedKV == "" {
		u := unix.Utsname{}
		if err := unix.Uname(&u); err != nil {
			return kernelrelease.KernelRelease{}, err
		}

		kr = string(bytes.Trim(u.Release[:], "\x00"))
		kv = string(bytes.Trim(u.Version[:], "\x00"))
	} else {
		kr = enforcedKR
		kv = enforcedKV
	}
	kernelRel := kernelrelease.FromString(kr)
	kernelRel.KernelVersion = formatVersion(kv)
	kernelRel.Architecture = kernelrelease.Architecture(runtime.GOARCH)
	// we don't use this, it is used by bpf build to customize the kernel config LOCALVERSION.
	// Expected value is empty.
	kernelRel.Extraversion = ""
	return kernelRel, nil
}

// formatVersion takes a kernelversion string (as taken from `uname -v`
// and extracts the first part of the string.
// Eg: '#1 SMP PREEMPT_DYNAMIC Tue, 10 Oct 2023 21:10:21 +0000' -> '1'.
// Eg: '#26~22.04.1-Ubuntu SMP Mon Apr 24 01:58:15 UTC 2023' -> '26~22.04.1-Ubuntu'.
func formatVersion(kv string) string {
	// Take eg: "#1 SMP PREEMPT_DYNAMIC Tue, 10 Oct 2023 21:10:21 +0000" and return "1".
	kv = strings.Trim(kv, "#")
	kv = strings.Split(kv, " ")[0]
	return kv
}
