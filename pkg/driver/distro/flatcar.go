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
	"os/exec"

	"github.com/blang/semver"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"
	"gopkg.in/ini.v1"

	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const flatcarRelocateScript = `
local -a tools=(
		scripts/basic/fixdep
		scripts/mod/modpost
		tools/objtool/objtool
	)
local -r hostld=$(ls /host/usr/lib64/ld-linux-*.so.*)
local -r kdir=/lib/modules/$(ls /lib/modules/)/build
echo "** Found host dl interpreter: ${hostld}"
for host_tool in ${tools[@]}; do
	t=${host_tool}
	tool=$(basename $t)
	tool_dir=$(dirname $t)
	host_tool=${kdir}/${host_tool}
	if [ ! -f ${host_tool} ]; then
		continue
	fi
	umount ${host_tool} 2>/dev/null || true
	mkdir -p /tmp/${tool_dir}/
	cp -a ${host_tool} /tmp/${tool_dir}/
	echo "** Setting host dl interpreter for $host_tool"
	patchelf --set-interpreter ${hostld} --set-rpath /host/usr/lib64 /tmp/${tool_dir}/${tool}
	mount -o bind /tmp/${tool_dir}/${tool} ${host_tool}
done
`

func init() {
	distros["flatcar"] = &flatcar{generic: &generic{}}
}

type flatcar struct {
	*generic
	versionID string
}

//nolint:gocritic // the method shall not be able to modify kr
func (f *flatcar) init(kr kernelrelease.KernelRelease, id string, cfg *ini.File) error {
	idKey, err := cfg.Section("").GetKey("VERSION_ID")
	if err != nil {
		return err
	}
	f.versionID = idKey.String()
	return f.generic.init(kr, id, cfg)
}

//nolint:gocritic // the method shall not be able to modify kr
func (f *flatcar) FixupKernel(kr kernelrelease.KernelRelease) kernelrelease.KernelRelease {
	kr.Version = semver.MustParse(f.versionID)
	kr.Fullversion = kr.Version.String()
	kr.FullExtraversion = ""
	return f.generic.FixupKernel(kr)
}

//nolint:gocritic // the method shall not be able to modify kr
func (f *flatcar) customizeBuild(ctx context.Context,
	printer *output.Printer,
	driverType drivertype.DriverType,
	_ kernelrelease.KernelRelease,
) (map[string]string, error) {
	switch driverType.String() {
	case drivertype.TypeBpf, drivertype.TypeKmod:
		break
	default:
		// nothing to do
		return nil, nil
	}
	printer.Logger.Info("Flatcar detected; relocating kernel tools.", printer.Logger.Args("version", f.versionID))
	out, err := exec.CommandContext(ctx, "/bin/bash", "-c", flatcarRelocateScript).Output()
	if err != nil {
		printer.DefaultText.Print(string(out))
	}
	return nil, err
}
