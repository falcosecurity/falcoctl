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
	"os"
	"path/filepath"

	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"
	"gopkg.in/ini.v1"

	"github.com/falcosecurity/falcoctl/internal/utils"
	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	kbuildExtraCppFlagsEnv = "KBUILD_EXTRA_CPPFLAGS"
	enableCos73Workaround  = "-DCOS_73_WORKAROUND"
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
func (c *cos) customizeBuild(ctx context.Context,
	printer *output.Printer,
	driverType drivertype.DriverType,
	kr kernelrelease.KernelRelease,
) (map[string]string, error) {
	switch driverType.String() {
	case drivertype.TypeBpf:
		break
	default:
		// nothing to do
		return nil, nil
	}
	printer.Logger.Info("COS detected, using COS kernel headers.", printer.Logger.Args("build ID", c.buildID))
	bpfKernelSrcURL := fmt.Sprintf("https://storage.googleapis.com/cos-tools/%s/kernel-headers.tgz", c.buildID)
	kr.Extraversion = "+"
	env, err := downloadKernelSrc(ctx, printer, &kr, bpfKernelSrcURL, 0)
	if err != nil {
		return nil, err
	}

	currKernelDir := env[kernelDirEnv]

	cosKernelDir := filepath.Join(currKernelDir, "usr", "src")
	entries, err := os.ReadDir(cosKernelDir)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no COS kernel src found")
	}
	cosKernelDir = filepath.Join(cosKernelDir, entries[0].Name())
	// Override env key
	env[kernelDirEnv] = cosKernelDir

	clangCompilerHeader := fmt.Sprintf("%s/include/linux/compiler-clang.h", cosKernelDir)
	err = utils.ReplaceLineInFile(clangCompilerHeader, "#define randomized_struct_fields_start", "", 1)
	if err != nil {
		return nil, err
	}
	err = utils.ReplaceLineInFile(clangCompilerHeader, "#define randomized_struct_fields_end", "", 1)
	if err != nil {
		return nil, err
	}

	baseVer, err := semver.Parse("11553.0.0")
	if err != nil {
		return nil, err
	}
	cosVer, err := semver.Parse(c.buildID)
	if err != nil {
		return nil, err
	}
	if cosVer.GT(baseVer) {
		env[kbuildExtraCppFlagsEnv] = enableCos73Workaround
	}
	return env, nil
}

// PreferredDriver is reimplemented since COS does not support kmod
//
//nolint:gocritic // the method shall not be able to modify kr
func (c *cos) PreferredDriver(kr kernelrelease.KernelRelease, allowedDriverTypes []drivertype.DriverType) drivertype.DriverType {
	for _, allowedDrvType := range allowedDriverTypes {
		if allowedDrvType.String() == drivertype.TypeKmod {
			continue
		default:
			break
		}
		if allowedDrvType.Supported(kr) {
			return allowedDrvType
		}
	}
	return nil
}
