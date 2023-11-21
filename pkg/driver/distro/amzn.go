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
	distros["amzn"] = &amzn{generic: &generic{}}
}

type amzn struct {
	*generic
}

//nolint:gocritic // the method shall not be able to modify kr
func (a *amzn) init(kr kernelrelease.KernelRelease, _ string, cfg *ini.File) error {
	idKey := cfg.Section("").Key("VERSION_ID")
	if idKey == nil {
		// OS-release without `VERSION_ID` (can it happen?)
		return fmt.Errorf("no VERSION_ID present for amzn")
	}
	// overwrite id
	newID := ""
	switch idKey.String() {
	case "2":
		newID = "amazonlinux2"
	case "2022":
		newID = "amazonlinux2022"
	case "2023":
		newID = "amazonlinux2023"
	default:
		newID = "amazonlinux"
	}
	return a.generic.init(kr, newID, cfg)
}
