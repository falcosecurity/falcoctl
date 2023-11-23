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

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"gopkg.in/ini.v1"
)

func init() {
	distros["talos"] = &talos{generic: &generic{}}
}

type talos struct {
	*generic
	versionID string
}

//nolint:gocritic // the method shall not be able to modify kr
func (t *talos) init(kr kernelrelease.KernelRelease, id string, cfg *ini.File) error {
	idKey, err := cfg.Section("").GetKey("VERSION_ID")
	if err != nil {
		return err
	}
	t.versionID = idKey.String()

	return t.generic.init(kr, id, cfg)
}

//nolint:gocritic // the method shall not be able to modify kr
func (t *talos) FixupKernel(kr kernelrelease.KernelRelease) kernelrelease.KernelRelease {
	kr.KernelVersion = fmt.Sprintf("1_%s", t.versionID)
	return kr
}
