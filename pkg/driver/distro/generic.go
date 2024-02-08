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

	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"
	"gopkg.in/ini.v1"

	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

// Parse start of string as "#NUMBER":
// eg1: "#1 SMP PREEMPT_DYNAMIC Tue, 10 Oct 2023 21:10:21 +0000" -> "1".
// eg2: #1-photon -> "1"
// Old falco-driver-loader method did:
// echo "${DRIVER_KERNEL_VERSION}" | sed 's/#\([[:digit:]]\+\).*/\1/'
// The regex does the same thing.
var genericKernelVersionRegex = regexp.MustCompile(`#(\d+).*`)

type generic struct {
	targetID string
}

//nolint:gocritic // the method shall not be able to modify kr
func (g *generic) init(_ kernelrelease.KernelRelease, id string, _ *ini.File) error {
	g.targetID = id
	return nil
}

func (g *generic) String() string {
	return g.targetID
}

//nolint:gocritic // the method shall not be able to modify kr
func (g *generic) FixupKernel(kr kernelrelease.KernelRelease) kernelrelease.KernelRelease {
	matches := genericKernelVersionRegex.FindStringSubmatch(kr.KernelVersion)
	if len(matches) == 2 {
		kr.KernelVersion = matches[1]
	}
	return kr
}

//nolint:gocritic // the method shall not be able to modify kr
func (g *generic) customizeBuild(_ context.Context,
	_ *output.Printer,
	_ drivertype.DriverType,
	_ kernelrelease.KernelRelease,
) (map[string]string, error) {
	return nil, nil
}

//nolint:gocritic // the method shall not be able to modify kr
func (g *generic) PreferredDriver(kr kernelrelease.KernelRelease) drivertype.DriverType {
	// Deadly simple default automatic selection
	var dType drivertype.DriverType
	switch {
	case kr.GTE(semver.MustParse("5.8.0")):
		dType, _ = drivertype.Parse(drivertype.TypeModernBpf)
	case kr.SupportsProbe():
		dType, _ = drivertype.Parse(drivertype.TypeBpf)
	default:
		dType, _ = drivertype.Parse(drivertype.TypeKmod)
	}
	return dType
}
