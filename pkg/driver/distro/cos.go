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
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"
	"gopkg.in/ini.v1"

	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

func init() {
	distros["cos"] = &cos{generic: &generic{}}
}

type cos struct {
	*generic
	buildID string
}

//nolint:gocritic // the method shall not be able to modify kr
func (c *cos) init(kr kernelrelease.KernelRelease, id string, cfg *ini.File) error {
	idKey, err := cfg.Section("").GetKey("BUILD_ID")
	if err != nil {
		return err
	}
	c.buildID = idKey.String()
	return c.generic.init(kr, id, cfg)
}

//nolint:gocritic // the method shall not be able to modify kr
func (c *cos) customizeBuild(_ context.Context,
	_ *output.Printer,
	_ drivertype.DriverType,
	_ kernelrelease.KernelRelease,
) (map[string]string, error) {
	return nil, nil
}

// PreferredDriver is reimplemented since COS does not support kmod
//
//nolint:gocritic // the method shall not be able to modify kr
func (c *cos) PreferredDriver(kr kernelrelease.KernelRelease, allowedDriverTypes []drivertype.DriverType) drivertype.DriverType {
	for _, allowedDrvType := range allowedDriverTypes {
		if allowedDrvType.String() == drivertype.TypeKmod {
			continue
		}
		if allowedDrvType.Supported(kr) {
			return allowedDrvType
		}
	}
	return nil
}
