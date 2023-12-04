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
	"strings"

	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"
	"gopkg.in/ini.v1"

	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

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
	// Take eg: "#1 SMP PREEMPT_DYNAMIC Tue, 10 Oct 2023 21:10:21 +0000" and return "1".
	kv := strings.TrimLeft(kr.KernelVersion, "#")
	kv = strings.Split(kv, " ")[0]
	kr.KernelVersion = kv
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
