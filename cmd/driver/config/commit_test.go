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
//

package driverconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	falcoName = "falco"
)

func newOptions() *driverConfigOptions {
	common := options.NewOptions()
	common.Initialize()

	// Parse the driver type.
	dType, _ := drivertype.Parse("modern_ebpf")
	return &driverConfigOptions{
		Common: common,
		Driver: &options.Driver{
			Type:     dType,
			Name:     falcoName,
			Repos:    []string{"https://download.falco.org/driver"},
			Version:  "6.0.0+driver",
			HostRoot: "/",
			Distro:   nil,
			Kr:       kernelrelease.KernelRelease{},
		},
		update:     false,
		namespace:  "",
		kubeconfig: "",
		configmap:  "",
		configDir:  "",
	}
}

func createFalcoConfigFile(cfg falcoCfg, configDir string) error {
	engineKind, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("unable to marshal falco config: %w", err)
	}

	// Write the engine configuration to a specialized config file.
	if err := os.WriteFile(filepath.Join(configDir, "falco.yaml"), engineKind, 0o600); err != nil {
		return fmt.Errorf("unable to write falco.yaml file: %w", err)
	}

	return nil
}

func createFalcoConfigMap(cfg falcoCfg, dataKey string) (*v1.ConfigMap, error) {
	engineKind, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal falco config: %w", err)
	}

	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      falcoName,
			Namespace: falcoName,
		},
		Data: map[string]string{
			dataKey: string(engineKind),
		},
	}

	return cm, nil
}

func TestDriverConfigOptions_Commit_Host(t *testing.T) {
	testCases := []struct {
		name     string
		args     func(t *testing.T) *driverConfigOptions
		expected func(t *testing.T, opt *driverConfigOptions, err error)
	}{
		{
			"no falco config file",
			func(t *testing.T) *driverConfigOptions {
				opt := newOptions()
				opt.configDir = "no-file-at-all"
				opt.update = true
				return opt
			},
			func(t *testing.T, opt *driverConfigOptions, err error) {
				require.Error(t, err, "should error since falco configuration file does not exist")
				require.ErrorContains(t, err, "open no-file-at-all/falco.yaml: no such file or directory")
			},
		},
		{
			"update-falco-config",
			func(t *testing.T) *driverConfigOptions {
				opt := newOptions()
				dir, err := os.MkdirTemp("", "falcoctl-driver-config-test")
				require.NoError(t, err)

				// Write falco configuration file.
				cfg := falcoCfg{engineCfg{Kind: "modern_ebpf"}}
				err = createFalcoConfigFile(cfg, dir)
				require.NoError(t, err)

				opt.configDir = dir
				return opt
			},
			func(t *testing.T, opt *driverConfigOptions, err error) {
				require.NoError(t, err, "should not error")

				// Config file.
				specCfgFile := filepath.Join(opt.configDir, "config.d", falcoDriverConfigFile)

				// Check that config file has been created.
				_, err = os.Stat(specCfgFile)
				require.NoError(t, err)

				content, err := os.ReadFile(specCfgFile)
				require.NoError(t, err)

				cfg := falcoCfg{}
				err = yaml.Unmarshal(content, &cfg)
				require.NoError(t, err)
				require.Equal(t, opt.Type.String(), cfg.Engine.Kind)
			},
		},
		{
			"falco-not-in-driver-mode",
			func(t *testing.T) *driverConfigOptions {
				opt := newOptions()
				dir, err := os.MkdirTemp("", "falcoctl-driver-config-test")
				require.NoError(t, err)

				// Write falco configuration file.
				cfg := falcoCfg{engineCfg{Kind: "nodriver"}}
				err = createFalcoConfigFile(cfg, dir)
				require.NoError(t, err)

				opt.configDir = dir
				return opt
			},
			func(t *testing.T, opt *driverConfigOptions, err error) {
				require.NoError(t, err, "should not error")

				// Config file.
				specCfgFile := filepath.Join(opt.configDir, "config.d", falcoDriverConfigFile)

				// Check that config file has been created.
				_, err = os.Stat(specCfgFile)
				require.True(t, os.IsNotExist(err))
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			opt := testCase.args(t)
			err := opt.Commit(context.Background(), nil, opt.Type)
			testCase.expected(t, opt, err)
		})
	}
}

func TestDriverConfigOptions_Commit_K8S(t *testing.T) {
	testCases := []struct {
		name     string
		args     func(t *testing.T) (*driverConfigOptions, *v1.ConfigMap)
		expected func(t *testing.T, opt *driverConfigOptions, err error)
	}{
		{
			"no falco configmap, wrong namespace",
			func(t *testing.T) (*driverConfigOptions, *v1.ConfigMap) {
				opt := newOptions()
				opt.namespace = "wrong-namespace"
				opt.configmap = falcoName

				cm, err := createFalcoConfigMap(falcoCfg{engineCfg{Kind: "modern_ebpf"}}, "falco.yaml")
				require.NoError(t, err)

				return opt, cm
			},
			func(t *testing.T, opt *driverConfigOptions, err error) {
				require.Error(t, err, "should error since falco configmap does not exist")
				require.ErrorContains(t, err, "unable to get configmap falco in namespace wrong-namespace")
			},
		},
		{
			"no falco configmap, wrong name",
			func(t *testing.T) (*driverConfigOptions, *v1.ConfigMap) {
				opt := newOptions()
				opt.namespace = falcoName
				opt.configmap = "wrong-name"

				cm, err := createFalcoConfigMap(falcoCfg{engineCfg{Kind: "modern_ebpf"}}, "falco.yaml")
				require.NoError(t, err)

				return opt, cm
			},
			func(t *testing.T, opt *driverConfigOptions, err error) {
				require.Error(t, err, "should error since falco configmap does not exist")
				require.ErrorContains(t, err, "unable to get configmap wrong-name in namespace falco")
			},
		},
		{
			"no falco config, wrong data key",
			func(t *testing.T) (*driverConfigOptions, *v1.ConfigMap) {
				opt := newOptions()
				opt.namespace = falcoName
				opt.configmap = falcoName

				cm, err := createFalcoConfigMap(falcoCfg{engineCfg{Kind: "modern_ebpf"}}, "wrong-data-key")
				require.NoError(t, err)

				return opt, cm
			},
			func(t *testing.T, opt *driverConfigOptions, err error) {
				require.Error(t, err, "should error since falco configmap does not exist")
				require.ErrorContains(t, err, "configMap falco does not contain key \"falco.yaml\"")
			},
		},
		{
			"update-falco-config",
			func(t *testing.T) (*driverConfigOptions, *v1.ConfigMap) {
				opt := newOptions()
				opt.namespace = falcoName
				opt.configmap = falcoName

				dir, err := os.MkdirTemp("", "falcoctl-driver-config-test")
				require.NoError(t, err)
				opt.configDir = dir

				cm, err := createFalcoConfigMap(falcoCfg{engineCfg{Kind: "modern_ebpf"}}, "falco.yaml")
				require.NoError(t, err)

				return opt, cm
			},

			func(t *testing.T, opt *driverConfigOptions, err error) {
				require.NoError(t, err, "should not error")

				// Config file.
				specCfgFile := filepath.Join(opt.configDir, "config.d", falcoDriverConfigFile)

				// Check that config file has been created.
				_, err = os.Stat(specCfgFile)
				require.NoError(t, err)

				content, err := os.ReadFile(specCfgFile)
				require.NoError(t, err)

				cfg := falcoCfg{}
				err = yaml.Unmarshal(content, &cfg)
				require.NoError(t, err)
				require.Equal(t, opt.Type.String(), cfg.Engine.Kind)
			},
		},
		{
			"falco-not-in-driver-mode",
			func(t *testing.T) (*driverConfigOptions, *v1.ConfigMap) {
				opt := newOptions()
				opt.namespace = falcoName
				opt.configmap = falcoName

				dir, err := os.MkdirTemp("", "falcoctl-driver-config-test")
				require.NoError(t, err)

				cm, err := createFalcoConfigMap(falcoCfg{engineCfg{Kind: "nodriver"}}, "falco.yaml")
				require.NoError(t, err)

				opt.configDir = dir
				return opt, cm
			},
			func(t *testing.T, opt *driverConfigOptions, err error) {
				require.NoError(t, err, "should not error")

				// Config file.
				specCfgFile := filepath.Join(opt.configDir, "config.d", falcoDriverConfigFile)

				// Check that config file has been created.
				_, err = os.Stat(specCfgFile)
				require.True(t, os.IsNotExist(err))
			},
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			opt, cm := testCase.args(t)
			// Create fake client.
			fakeClient := fake.NewSimpleClientset(cm)
			err := opt.Commit(context.Background(), fakeClient, opt.Type)
			testCase.expected(t, opt, err)
		})
	}
}
