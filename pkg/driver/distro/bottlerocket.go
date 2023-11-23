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
	"strings"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"gopkg.in/ini.v1"
)

func init() {
	distros["bottlerocket"] = &bottlerocket{generic: &generic{}}
}

type bottlerocket struct {
	*generic
	variantID string
	versionID string
}

//nolint:gocritic // the method shall not be able to modify kr
func (b *bottlerocket) init(kr kernelrelease.KernelRelease, id string, cfg *ini.File) error {
	idKey, err := cfg.Section("").GetKey("VERSION_ID")
	if err != nil {
		return err
	}
	b.versionID = idKey.String()

	idKey, err = cfg.Section("").GetKey("VARIANT_ID")
	if err != nil {
		return err
	}
	b.variantID = strings.Split(idKey.String(), "-")[0]

	return b.generic.init(kr, id, cfg)
}

//nolint:gocritic // the method shall not be able to modify kr
func (b *bottlerocket) FixupKernel(kr kernelrelease.KernelRelease) kernelrelease.KernelRelease {
	kr.KernelVersion = fmt.Sprintf("1_%s-%s", b.versionID, b.variantID)
	return kr
}
