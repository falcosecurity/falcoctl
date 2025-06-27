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

package options

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"

	"github.com/falcosecurity/falcoctl/internal/config"
	driverdistro "github.com/falcosecurity/falcoctl/pkg/driver/distro"
	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/enum"
)

// DriverTypes data structure for driver types.
type DriverTypes struct {
	*enum.Enum
}

// NewDriverTypes returns a new Enum configured for the driver types.
func NewDriverTypes() *DriverTypes {
	types := drivertype.GetTypes()
	sort.Strings(types)
	return &DriverTypes{
		// Default value is not used.
		// This enum is only used to print allowed values.
		Enum: enum.NewEnum(types, drivertype.TypeModernBpf),
	}
}

// Driver defines options that are common while interacting with driver commands.
type Driver struct {
	Type     drivertype.DriverType
	Name     string
	Repos    []string
	Pubkey   string
	NoVerify bool
	Version  string
	HostRoot string
	Distro   driverdistro.Distro
	Kr       kernelrelease.KernelRelease
}

// ToDriverConfig maps a Driver options to Driver config struct.
func (d *Driver) ToDriverConfig() *config.Driver {
	return &config.Driver{
		Type:     []string{d.Type.String()},
		Name:     d.Name,
		Repos:    d.Repos,
		Pubkey:   d.Pubkey,
		NoVerify: d.NoVerify,
		Version:  d.Version,
		HostRoot: d.HostRoot,
	}
}

// Validate runs all validators steps for Driver options.
func (d *Driver) Validate() error {
	if !filepath.IsAbs(d.HostRoot) {
		return fmt.Errorf("host-root must be an absolute path (%s)", d.HostRoot)
	}

	if d.Version == "" {
		return errors.New("version is mandatory and cannot be empty")
	}

	for _, repo := range d.Repos {
		_, err := url.ParseRequestURI(repo)
		if err != nil {
			return fmt.Errorf("repo must be a valid url (%s): %w", repo, err)
		}
	}

	return nil
}
