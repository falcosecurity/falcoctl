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
	"os"
	"path/filepath"
	"testing"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
)

func TestDiscoverDistro(t *testing.T) {
	hostRoot := "."
	etcDir := filepath.Join(hostRoot, "etc")
	osReleaseFile := filepath.Join(etcDir, "os-release")

	type osID struct {
		OsID string `ini:"ID"`
	}

	type testCase struct {
		krInput        string
		preFn          func() error
		postFn         func()
		distroExpected interface{}
		errExpected    bool
	}
	testCases := []testCase{
		{
			// No os-release
			krInput: "5.10.0",
			preFn: func() error {
				return nil
			},
			postFn:         func() {},
			distroExpected: nil,
			errExpected:    true,
		},
		{
			// os-release empty (without ID)
			krInput: "5.10.0",
			preFn: func() error {
				_, err := os.Create(osReleaseFile)
				return err
			},
			postFn: func() {
				_ = os.Remove(osReleaseFile)
			},
			distroExpected: nil,
			errExpected:    false,
		},
		{
			// os-release ID "foo" mapped to generic
			krInput: "5.10.0",
			preFn: func() error {
				f := ini.Empty()
				err := f.ReflectFrom(&osID{"foo"})
				if err != nil {
					return err
				}
				return f.SaveTo(osReleaseFile)
			},
			postFn: func() {
				_ = os.Remove(osReleaseFile)
			},
			distroExpected: &generic{},
			errExpected:    false,
		},
		{
			// os-release ID "centos" mapped to centos
			krInput: "5.10.0",
			preFn: func() error {
				f := ini.Empty()
				err := f.ReflectFrom(&osID{"centos"})
				if err != nil {
					return err
				}
				return f.SaveTo(osReleaseFile)
			},
			postFn: func() {
				_ = os.Remove(osReleaseFile)
			},
			distroExpected: &centos{},
			errExpected:    false,
		},
		{
			// os-release ID "talos" fails to map to talos because no VERSION_ID is present in the ini
			krInput: "5.10.0",
			preFn: func() error {
				f := ini.Empty()
				err := f.ReflectFrom(&osID{"talos"})
				if err != nil {
					return err
				}
				return f.SaveTo(osReleaseFile)
			},
			postFn: func() {
				_ = os.Remove(osReleaseFile)
			},
			distroExpected: &generic{},
			errExpected:    false,
		},
		{
			// os-release ID "talos" maps to talos
			krInput: "5.10.0",
			preFn: func() error {
				type talosCfg struct {
					OsID      string `ini:"ID"`
					VersionID string `ini:"VERSION_ID"`
				}
				f := ini.Empty()
				err := f.ReflectFrom(&talosCfg{
					OsID:      "talos",
					VersionID: "1.10.0",
				})
				if err != nil {
					return err
				}
				return f.SaveTo(osReleaseFile)
			},
			postFn: func() {
				_ = os.Remove(osReleaseFile)
			},
			distroExpected: &talos{},
			errExpected:    false,
		},
		{
			// os-release ID "bottlerocket" maps to bottlerocket
			krInput: "5.10.0",
			preFn: func() error {
				type brCfg struct {
					OsID      string `ini:"ID"`
					VersionID string `ini:"VERSION_ID"`
					VariantID string `ini:"VARIANT_ID"`
				}
				f := ini.Empty()
				err := f.ReflectFrom(&brCfg{
					OsID:      "bottlerocket",
					VersionID: "1.10.0",
					VariantID: "aws",
				})
				if err != nil {
					return err
				}
				return f.SaveTo(osReleaseFile)
			},
			postFn: func() {
				_ = os.Remove(osReleaseFile)
			},
			distroExpected: &bottlerocket{},
			errExpected:    false,
		},
		{
			// No os-release  but "centos-release" file present maps to centos
			krInput: "5.10.0",
			preFn: func() error {
				_, err := os.Create(filepath.Join(etcDir, "centos-release"))
				return err
			},
			postFn: func() {
				_ = os.Remove(filepath.Join(etcDir, "centos-release"))
			},
			distroExpected: &centos{},
			errExpected:    false,
		},
		{
			// No os-release  but "VERSION" file present maps to minikube
			krInput: "5.10.0",
			preFn: func() error {
				return os.WriteFile(filepath.Join(etcDir, "VERSION"), []byte("v1.26.0-1655407986-14197"), os.ModePerm)
			},
			postFn: func() {
				_ = os.Remove(filepath.Join(etcDir, "VERSION"))
			},
			distroExpected: &minikube{},
			errExpected:    false,
		},
	}

	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(etcDir)

	for _, tCase := range testCases {
		err := tCase.preFn()
		require.NoError(t, err)
		kr := kernelrelease.FromString(tCase.krInput)
		d, err := DiscoverDistro(kr, hostRoot)
		if tCase.errExpected {
			assert.Error(t, err)
		} else {
			assert.IsType(t, tCase.distroExpected, d)
		}
		tCase.postFn()
	}
}
