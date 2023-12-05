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

// Package drivertype implements all the driver type specific logic.
package drivertype

import (
	"fmt"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"

	"github.com/falcosecurity/falcoctl/pkg/output"
)

var driverTypes = map[string]DriverType{}

// DriverType is the interface that wraps driver types.
type DriverType interface {
	fmt.Stringer
	Cleanup(printer *output.Printer, driverName string) error
	Load(printer *output.Printer, driverName string, fallback bool) error
	Extension() string
	HasArtifacts() bool
	Build(ctx context.Context, printer *output.Printer, kr kernelrelease.KernelRelease,
		driverName, driverVersion string, env map[string]string) (string, error)
}

// GetTypes return the list of supported driver types.
func GetTypes() []string {
	driverTypesSlice := make([]string, 0)
	for key := range driverTypes {
		driverTypesSlice = append(driverTypesSlice, key)
	}
	// auto is a sentinel value to enable automatic driver selection logic,
	// but it is not mapped to any DriverType
	driverTypesSlice = append(driverTypesSlice, "auto")
	return driverTypesSlice
}

// Parse parses a driver type string and returns the corresponding DriverType object or an error.
func Parse(driverType string) (DriverType, error) {
	if dType, ok := driverTypes[driverType]; ok {
		return dType, nil
	}
	return nil, fmt.Errorf("wrong driver type specified: %s", driverType)
}
