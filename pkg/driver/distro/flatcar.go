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
set -euo pipefail

shopt -s nullglob

hostlds=( /host/usr/lib64/ld-linux-*.so.* )
if [[ ${#hostlds[@]} -eq 0 ]]; then
	echo "** no dynamic loaders found"
	exit 1
fi
if [[ ${#hostlds[@]} -gt 1 ]]; then
	echo "** more than one fitting dynamic loader found, picking first"
fi
hostld=${hostlds[0]}
echo "** Found host dynamic loader: ${hostld}"

kdirs=( /host/lib/modules/*/build )
if [[ ${#kdirs[@]} -eq 0 ]]; then
	echo "** no kernel module tools directories found"
	exit 1
fi
if [[ ${#kdirs[@]} -gt 1 ]]; then
	echo "** more than one fitting kernel module tools directory found, picking first"
fi
kdir=${kdirs[0]}
echo "** Found kernel tools directory: ${kdir}"

tools=(
	scripts/basic/fixdep
	scripts/mod/modpost
	tools/objtool/objtool
)

tmp_dir=$(mktemp -d)
for tool in "${tools[@]}"; do
	host_tool=${kdir}/${tool}
	if [[ ! -f ${host_tool} ]]; then
		echo "${tool@Q} not found in ${kdir@Q}, not patching"
		continue
	fi
	umount "${host_tool}" 2>/dev/null || true
	tmp_tool=${tmp_dir}/${tool}
	mkdir -p "$(dirname "${tmp_tool}")"
	cp -a "${host_tool}" "${tmp_tool}"
	echo "** Setting host dynamic loader for ${tool@Q}"
	patchelf \
		--set-interpreter "${hostld}" \
		--set-rpath /host/usr/lib64 \
		"${tmp_tool}"
	mount -o bind "${tmp_tool}" "${host_tool}"
done
rm -rf "${tmp_dir}"
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
	out, err := exec.CommandContext(ctx, "/bin/bash", "-c", flatcarRelocateScript).CombinedOutput()
	if err != nil {
		printer.DefaultText.Print(string(out))
	}
	return nil, err
}
