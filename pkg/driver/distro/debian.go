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
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"

	"github.com/falcosecurity/falcoctl/internal/utils"
	driverkernel "github.com/falcosecurity/falcoctl/pkg/driver/kernel"
)

func init() {
	distros["debian"] = &debian{generic: &generic{}}
}

type debian struct {
	*generic
}

var debianKernelReleaseRegex = regexp.MustCompile(`-?(rt-|cloud-|)(amd64|arm64)`)
var debianKernelVersionRegex = regexp.MustCompile(`\d+\.\d+\.\d+-\d+`)

func (d *debian) check() bool {
	exist, _ := utils.FileExists(d.releaseFile())
	return exist
}

func (d *debian) releaseFile() string {
	return filepath.Clean(filepath.Join(hostRoot, "etc", "debian_version"))
}

//nolint:gocritic // the method shall not be able to modify kr
func (d *debian) FixupKernel(kr kernelrelease.KernelRelease) kernelrelease.KernelRelease {
	// Workaround: debian kernelreleases might not be actual kernel running;
	// instead, they might be the Debian kernel package
	// providing the compatible kernel ABI
	// See https://lists.debian.org/debian-user/2017/03/msg00485.html
	// Real kernel release is embedded inside the kernel version.
	// Moreover, kernel arch, when present, is attached to the former,
	// therefore make sure to properly take it and attach it to the latter.
	// Moreover, we support 3 flavors for debian kernels: cloud, rt and normal.
	// KERNEL-RELEASE will have a `-rt`, or `-cloud` if we are in one of these flavors.
	// Manage it to download the correct driver.
	//
	// Example: KERNEL_RELEASE="5.10.0-0.deb10.22-rt-amd64" and `uname -v`="5.10.178-3"
	// should lead to: KERNEL_RELEASE="5.10.178-3-rt-amd64"
	archExtra := ""
	if debianKernelReleaseRegex.MatchString(kr.FullExtraversion) {
		matches := debianKernelReleaseRegex.FindStringSubmatch(kr.FullExtraversion)
		// -rt-amd64
		archExtra = fmt.Sprintf("-%s%s", matches[1], matches[2])
	}
	if debianKernelVersionRegex.MatchString(kr.KernelVersion) {
		newKV := debianKernelVersionRegex.FindStringSubmatch(kr.KernelVersion)[0]
		// Real kernel release becomes: "5.10.178-3-rt-amd64"
		realKernelReleaseStr := fmt.Sprintf("%s%s", newKV, archExtra)
		// Parse it once again to a KernelRelease struct
		kr, _ = driverkernel.FetchInfo(realKernelReleaseStr, "1")
		return kr
	}
	// No substitutions needed; call generic FixupKernel.
	return d.generic.FixupKernel(kr)
}
