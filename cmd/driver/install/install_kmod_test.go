// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 The Falco Authors
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

//go:build linux

package driverinstall

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/pterm/pterm"
	"github.com/stretchr/testify/require"

	drivercleanup "github.com/falcosecurity/falcoctl/cmd/driver/cleanup"
	driverdistro "github.com/falcosecurity/falcoctl/pkg/driver/distro"
	driverkernel "github.com/falcosecurity/falcoctl/pkg/driver/kernel"
	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

type kmodFixture struct {
	common *options.Common
	driver *options.Driver
	state  string
	cache  string
}

func newKmodFixture(t *testing.T, statusCode int) *kmodFixture {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("FALCOCTL_TEST_STATE", root)
	bin := filepath.Join(root, "bin")
	require.NoError(t, os.Mkdir(bin, 0o755))
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	scripts := map[string]string{
		"lsmod": `if [ -f "$FALCOCTL_TEST_STATE/loaded" ]; then echo 'falco 123 0'; fi`,
		"rmmod": `echo rmmod >> "$FALCOCTL_TEST_STATE/calls"; rm "$FALCOCTL_TEST_STATE/loaded"`,
		"insmod": `echo insmod >> "$FALCOCTL_TEST_STATE/calls"
if [ -n "$FALCOCTL_TEST_INSMOD_FAIL" ]; then exit 1; fi
touch "$FALCOCTL_TEST_STATE/loaded"`,
		"modprobe": `echo modprobe >> "$FALCOCTL_TEST_STATE/calls"; test -f "$FALCOCTL_TEST_STATE/installed"`,
		"chcon":    "exit 0",
		"dkms": `echo "dkms $*" >> "$FALCOCTL_TEST_STATE/calls"
case "$1" in
status) if [ -f "$FALCOCTL_TEST_STATE/installed" ]; then echo 'falco/11.0.0+driver, 6.1.0, x86_64: installed'; fi ;;
remove) rm "$FALCOCTL_TEST_STATE/installed" ;;
*) exit 1 ;;
esac`,
	}
	for name, script := range scripts {
		require.NoError(t, os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+script+"\n"), 0o755))
	}
	for _, file := range []string{"loaded", "installed", "calls"} {
		require.NoError(t, os.WriteFile(filepath.Join(root, file), nil, 0o600))
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte("test module"))
	}))
	t.Cleanup(server.Close)

	require.NoError(t, os.Mkdir(filepath.Join(root, "etc"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "etc", "os-release"), []byte("ID=debian\n"), 0o600))
	kr, err := driverkernel.FetchInfo("", "")
	require.NoError(t, err)
	kr.KernelVersion = "#1 test"
	distro, err := driverdistro.Discover(kr, root)
	require.NoError(t, err)
	driverType, err := drivertype.Parse(drivertype.TypeKmod)
	require.NoError(t, err)

	return &kmodFixture{
		common: &options.Common{Printer: output.NewPrinter(pterm.LogLevelInfo, pterm.LogFormatterJSON, io.Discard)},
		driver: &options.Driver{
			Type: driverType, Name: "falco", Version: "11.0.0+driver", Repos: []string{server.URL},
			HostRoot: root, Distro: distro, Kr: kr,
		},
		state: root,
		cache: filepath.Join(root, ".falco", "11.0.0+driver", kr.Architecture.ToNonDeb(),
			fmt.Sprintf("falco_debian_%s_1.ko", kr.String())),
	}
}

func (f *kmodFixture) install(args ...string) error {
	command := NewDriverInstallCmd(context.Background(), f.common, f.driver)
	command.SilenceErrors = true
	command.SilenceUsage = true
	command.SetArgs(args)
	return command.Execute()
}

func (f *kmodFixture) warmCache(t *testing.T) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(f.cache), 0o755))
	require.NoError(t, os.WriteFile(f.cache, []byte("cached module"), 0o600))
}

func (f *kmodFixture) calls(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.state, "calls"))
	require.NoError(t, err)
	return string(data)
}

func TestKmodInstallPreservesDKMS(t *testing.T) {
	for _, cached := range []bool{false, true} {
		name := "download"
		if cached {
			name = "cache"
		}
		t.Run(name, func(t *testing.T) {
			f := newKmodFixture(t, http.StatusOK)
			if cached {
				f.warmCache(t)
			}
			for range 2 {
				require.NoError(t, f.install())
				require.FileExists(t, filepath.Join(f.state, "installed"))
				require.FileExists(t, filepath.Join(f.state, "loaded"))
			}
			require.Equal(t, "rmmod\ninsmod\nrmmod\ninsmod\n", f.calls(t))
		})
	}
}

func TestKmodInstallFailurePreservesExistingModule(t *testing.T) {
	f := newKmodFixture(t, http.StatusNotFound)
	require.ErrorContains(t, f.install("--compile=false"), "unable to find a prebuilt driver")
	require.FileExists(t, filepath.Join(f.state, "installed"))
	require.FileExists(t, filepath.Join(f.state, "loaded"))
	require.Equal(t, "modprobe\n", f.calls(t))
}

func TestKmodCachedInstallDoesNotRequireDKMS(t *testing.T) {
	f := newKmodFixture(t, http.StatusOK)
	f.warmCache(t)
	require.NoError(t, os.Remove(filepath.Join(f.state, "installed")))
	require.NoError(t, f.install("--compile=false"))
	require.NoFileExists(t, filepath.Join(f.state, "installed"))
	require.FileExists(t, filepath.Join(f.state, "loaded"))
	require.Equal(t, "rmmod\ninsmod\n", f.calls(t))
}

func TestKmodCompileDoesNotAcceptCachedArtifactWithoutSources(t *testing.T) {
	f := newKmodFixture(t, http.StatusNotFound)
	f.driver.Version = "falcoctl-test-missing-sources"
	f.cache = filepath.Join(f.state, ".falco", f.driver.Version, f.driver.Kr.Architecture.ToNonDeb(), filepath.Base(f.cache))
	f.warmCache(t)
	require.ErrorContains(t, f.install("--download=false"), "driver sources for falcoctl-test-missing-sources are not available")
	require.FileExists(t, filepath.Join(f.state, "installed"))
	require.FileExists(t, filepath.Join(f.state, "loaded"))
	require.Equal(t, "modprobe\n", f.calls(t))
}

func TestKmodInstallReportsLoadFailure(t *testing.T) {
	f := newKmodFixture(t, http.StatusOK)
	f.warmCache(t)
	t.Setenv("FALCOCTL_TEST_INSMOD_FAIL", "1")
	require.Error(t, f.install())
	require.FileExists(t, filepath.Join(f.state, "installed"))
	require.Equal(t, "rmmod\ninsmod\n", f.calls(t))
}

func TestKmodInstallForAnotherKernelDoesNotLoad(t *testing.T) {
	f := newKmodFixture(t, http.StatusOK)
	kr := f.driver.Kr
	f.driver.Kr = kernelrelease.FromString("0.0.1-falcoctl-test")
	f.driver.Kr.Architecture = kr.Architecture
	f.driver.Kr.KernelVersion = kr.KernelVersion
	require.NoError(t, f.install())
	require.FileExists(t, filepath.Join(f.state, "installed"))
	require.FileExists(t, filepath.Join(f.state, "loaded"))
	require.Empty(t, f.calls(t))
}

func TestKmodCleanupStillRemovesDKMS(t *testing.T) {
	f := newKmodFixture(t, http.StatusOK)
	command := drivercleanup.NewDriverCleanupCmd(context.Background(), f.common, f.driver)
	command.SetArgs(nil)
	require.NoError(t, command.Execute())
	require.NoFileExists(t, filepath.Join(f.state, "installed"))
	require.NoFileExists(t, filepath.Join(f.state, "loaded"))
	require.Equal(t, "rmmod\ndkms status -m falco\ndkms remove -m falco -v 11.0.0+driver --all\n", f.calls(t))
}
