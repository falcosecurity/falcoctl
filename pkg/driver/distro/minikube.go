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
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"

	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

func init() {
	distros["minikube"] = &minikube{generic: &generic{}}
}

type minikube struct {
	*generic
	version string
}

var minikubeVersionRegex = regexp.MustCompile(`(\d+(\.\d+){2})`)

// check() will also load minikube version, because minikube has a different
// code path from other "checker" distros.
func (m *minikube) check() bool {
	file, err := os.Open(m.releaseFile())
	if err == nil {
		defer func() {
			_ = file.Close()
		}()

		// Extract the minikube version.
		// Eg: for minikube version "v1.26.0-1655407986-14197"
		// the extracted version will be "1.26.0"
		bytes, err := io.ReadAll(file)
		if err != nil {
			return false
		}
		matches := minikubeVersionRegex.FindStringSubmatch(string(bytes))
		if len(matches) == 0 {
			return false
		}
		m.version = matches[1]
		return true
	}
	return false
}

func (m *minikube) releaseFile() string {
	return filepath.Clean(filepath.Join(hostRoot, "etc", "VERSION"))
}

//nolint:gocritic // the method shall not be able to modify kr
func (m *minikube) FixupKernel(kr kernelrelease.KernelRelease) kernelrelease.KernelRelease {
	kr.KernelVersion = fmt.Sprintf("1_%s", m.version)
	return kr
}

//nolint:gocritic // the method shall not be able to modify kr
func (m *minikube) customizeBuild(_ context.Context,
	_ *output.Printer,
	_ drivertype.DriverType,
	_ kernelrelease.KernelRelease,
) (map[string]string, error) {
	return nil, nil
}
