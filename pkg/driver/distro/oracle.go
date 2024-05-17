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
	"strings"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"

	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
)

func init() {
	distros["ol"] = &ol{generic: &generic{}}
}

type ol struct {
	*generic
}

//nolint:gocritic // the method shall not be able to modify kr
func (o *ol) PreferredDriver(kr kernelrelease.KernelRelease, allowedDriverTypes []drivertype.DriverType) drivertype.DriverType {
	for _, allowedDrvType := range allowedDriverTypes {
		// Skip dkms on UEK hosts because it will always fail
		if allowedDrvType.String() == drivertype.TypeKmod && strings.Contains(kr.String(), "uek") {
			continue
		}
		if allowedDrvType.Supported(kr) {
			return allowedDrvType
		}
	}
	return nil
}
