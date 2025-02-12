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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/falcosecurity/falcoctl/pkg/output"
	"github.com/pterm/pterm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/ini.v1"
)

func TestDiscoverDistro(t *testing.T) {
	localHostRoot := os.TempDir()
	etcDir := localHostRoot + "/etc"
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
			distroExpected: &generic{},
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
			distroExpected: &generic{},
			errExpected:    true,
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
			// os-release ID "ol" maps to oracle
			krInput: "5.10.0-2047.510.5.5.el7uek.x86_64",
			preFn: func() error {
				type brCfg struct {
					OsID string `ini:"ID"`
				}
				f := ini.Empty()
				err := f.ReflectFrom(&brCfg{
					OsID: "ol",
				})
				if err != nil {
					return err
				}
				return f.SaveTo(osReleaseFile)
			},
			postFn: func() {
				_ = os.Remove(osReleaseFile)
			},
			distroExpected: &ol{},
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
		d, err := Discover(kr, localHostRoot)
		if tCase.errExpected {
			assert.Error(t, err)
		}
		assert.IsType(t, tCase.distroExpected, d)
		tCase.postFn()
	}
}

func TestVerifyDownloadedSignature(t *testing.T) {
	type testCase struct {
		name                 string
		downloadedDriverDest string
		pubkey               string
		valid                bool
	}
	testCases := []testCase{
		{"valid local pubkey", "testdata/hello.txt", "testdata/key.pub", true},
		// {"valid remote pubkey", "testdata/hello.txt", "https://raw.githubusercontent.com/LucaGuerra/falcoctl/8875a534256686a936213b8b8dc5bbf74b5febfc/internal/signature/testdata/key.pub", true},
		// {"invalid remote pubkey", "testdata/hello.txt", "https://raw.githubusercontent.com/LucaGuerra/falcoctl/8875a534256686a936213b8b8dc5bbf74b5febfc/internal/signature/testdata/does_not_exist.pub", false},
		{"missing signature", "testdata/hello2.txt", "testdata/key.pub", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			printer := output.NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterJSON, os.Stdout)

			err := VerifyDownloadedSignature(context.Background(), printer, tc.downloadedDriverDest, tc.pubkey, "")
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
