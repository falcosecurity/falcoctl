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
	"regexp"
	"strings"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"gopkg.in/ini.v1"
)

func init() {
	distros["ubuntu"] = &ubuntu{generic: &generic{}}
}

type ubuntu struct {
	*generic
}

var ubuntuTargetIDRegex = regexp.MustCompile(`-([a-zA-Z]+)(-.*)?$`)

//nolint:gocritic // the method shall not be able to modify kr
func (u *ubuntu) init(kr kernelrelease.KernelRelease, _ string, f *ini.File) error {
	// # Extract the flavor from the kernelrelease
	// # Examples:
	//   # 5.0.0-1028-aws-5.0 -> ubuntu-aws
	//   # 5.15.0-1009-aws -> ubuntu-aws
	flavor := "generic"
	if ubuntuTargetIDRegex.MatchString(kr.FullExtraversion) {
		flavor = ubuntuTargetIDRegex.FindStringSubmatch(kr.FullExtraversion)[1]
	}
	return u.generic.init(kr, "ubuntu-"+flavor, f)
}

//nolint:gocritic // the method shall not be able to modify kr
func (u *ubuntu) FixupKernel(kr kernelrelease.KernelRelease) kernelrelease.KernelRelease {
	// In the case that the kernelversion isn't just a number
	// we keep also the remaining part excluding `-Ubuntu`.
	// E.g.:
	// from the following `uname -v` result
	// `#26~22.04.1-Ubuntu SMP Mon Apr 24 01:58:15 UTC 2023`
	// we obtain the kernelversion`26~22.04.1`.
	// Another example: "#1 SMP PREEMPT_DYNAMIC Tue, 10 Oct 2023 21:10:21 +0000" and return "1".
	kv := strings.TrimLeft(kr.KernelVersion, "#")
	kv = strings.Split(kv, " ")[0]
	kr.KernelVersion = strings.TrimSuffix(kv, "-Ubuntu")
	return kr
}
