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

package driverconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/falcosecurity/falcoctl/internal/config"
	drivertype "github.com/falcosecurity/falcoctl/pkg/driver/type"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

const (
	longConfig = `Configure a driver for future usages with other driver subcommands.
It will also update local Falco configuration or k8s configmap depending on the environment where it is running, to let Falco use chosen driver.
Only supports deployments of Falco that use a driver engine, i.e.: one between kmod and modern-ebpf.
If engine.kind key is set to a non-driver driven engine, Falco configuration won't be touched.
`
	falcoConfigFile       = "falco.yaml"
	falcoDriverConfigFile = "engine-kind-falcoctl.yaml"
)

type driverConfigOptions struct {
	*options.Common
	*options.Driver
	update     bool
	namespace  string
	kubeconfig string
	configmap  string
	configDir  string
}

type engineCfg struct {
	Kind string `yaml:"kind"`
}
type falcoCfg struct {
	Engine engineCfg `yaml:"engine"`
}

// NewDriverConfigCmd configures a driver and stores it in config.
func NewDriverConfigCmd(ctx context.Context, opt *options.Common, driver *options.Driver) *cobra.Command {
	o := driverConfigOptions{
		Common: opt,
		Driver: driver,
	}

	cmd := &cobra.Command{
		Use:                   "config [flags]",
		DisableFlagsInUseLine: true,
		Short:                 "Configure a driver",
		Long:                  longConfig,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			viper.AutomaticEnv()

			_ = viper.BindPFlag("driver.config.configmap", cmd.Flags().Lookup("configmap"))
			_ = viper.BindPFlag("driver.config.namespace", cmd.Flags().Lookup("namespace"))
			_ = viper.BindPFlag("driver.config.update_falco", cmd.Flags().Lookup("update-falco"))
			_ = viper.BindPFlag("driver.config.kubeconfig", cmd.Flags().Lookup("kubeconfig"))
			_ = viper.BindPFlag("driver.config.configdir", cmd.Flags().Lookup("falco-config-dir"))

			o.configmap = viper.GetString("driver.config.configmap")
			o.namespace = viper.GetString("driver.config.namespace")
			o.kubeconfig = viper.GetString("driver.config.kubeconfig")
			o.update = viper.GetBool("driver.config.update_falco")
			o.configDir = viper.GetString("driver.config.configdir")

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunDriverConfig(ctx)
		},
	}

	cmd.Flags().BoolVar(&o.update, "update-falco", true, "Whether to overwrite Falco configuration")
	cmd.Flags().StringVar(&o.namespace, "namespace", "", "Kubernetes namespace.")
	cmd.Flags().StringVar(&o.kubeconfig, "kubeconfig", "", "Kubernetes config.")
	cmd.Flags().StringVar(&o.configmap, "configmap", "", "Falco configmap name.")
	cmd.Flags().StringVar(&o.configDir, "falco-config-dir", "/etc/falco", "Falco configuration directory.")

	return cmd
}

// RunDriverConfig implements the driver configuration command.
func (o *driverConfigOptions) RunDriverConfig(ctx context.Context) error {
	o.Printer.Logger.Info("Running falcoctl driver config", o.Printer.Logger.Args(
		"name", o.Driver.Name,
		"version", o.Driver.Version,
		"type", o.Driver.Type.String(),
		"host-root", o.Driver.HostRoot,
		"repos", strings.Join(o.Driver.Repos, ",")))

	if o.update {
		var cl kubernetes.Interface
		var err error

		if o.namespace != "" {
			// Create a new clientset.
			if cl, err = setupClient(o.kubeconfig); err != nil {
				return err
			}
		}

		if err := o.Commit(ctx, cl, o.Driver.Type); err != nil {
			return err
		}
	}
	o.Printer.Logger.Info("Storing falcoctl driver config")
	return config.StoreDriver(o.Driver.ToDriverConfig(), o.ConfigFile)
}

func checkFalcoRunsWithDrivers(engineKind string) bool {
	// Modify the data in the ConfigMap/Falco config file ONLY if engine.kind is set to a known driver type.
	// This ensures that we modify the config only for Falcos running with drivers, and not plugins.
	// Scenario: user has multiple Falco pods deployed in its cluster, one running with driver,
	// other running with plugins. We must only touch the one running with driver.
	if _, err := drivertype.Parse(engineKind); err != nil {
		return false
	}
	return true
}

func (o *driverConfigOptions) IsRunningInDriverModeHost() (bool, error) {
	o.Printer.Logger.Debug("Checking if Falco is running in driver mode on host system")

	falcoCfgFile := filepath.Join(o.configDir, falcoConfigFile)
	yamlFile, err := os.ReadFile(filepath.Clean(falcoCfgFile))
	if err != nil {
		return false, err
	}
	cfg := falcoCfg{}
	if err = yaml.Unmarshal(yamlFile, &cfg); err != nil {
		return false, fmt.Errorf("unable to unmarshal falco.yaml to falcoCfg struct: %w", err)
	}

	return checkFalcoRunsWithDrivers(cfg.Engine.Kind), nil
}

func (o *driverConfigOptions) IsRunningInDriverModeK8S(ctx context.Context, cl kubernetes.Interface) (bool, error) {
	o.Printer.Logger.Debug("Checking if Falco is running in driver mode in Kubernetes")

	configMap, err := cl.CoreV1().ConfigMaps(o.namespace).Get(ctx, o.configmap, metav1.GetOptions{})

	if err != nil {
		return false, fmt.Errorf("unable to get configmap %s in namespace %s: %w", o.configmap, o.namespace, err)
	}

	// Check that this is a Falco config map
	falcoYaml, present := configMap.Data["falco.yaml"]
	if !present {
		o.Printer.Logger.Debug("Skip non Falco-related config map",
			o.Printer.Logger.Args("configMap", configMap.Name))
		return false, fmt.Errorf("configMap %s does not contain key \"falco.yaml\"", o.configmap)
	}

	// Check that Falco is configured to run with a driver
	var falcoConfig falcoCfg
	err = yaml.Unmarshal([]byte(falcoYaml), &falcoConfig)
	if err != nil {
		return false, fmt.Errorf("unable to unmarshal falco.yaml to falcoCfg struct: %w", err)
	}

	return checkFalcoRunsWithDrivers(falcoConfig.Engine.Kind), nil
}

// Commit saves the updated driver type to Falco config,
// in a specialized configuration file under /etc/falco/config.d.
func (o *driverConfigOptions) Commit(ctx context.Context, cl kubernetes.Interface, driverType drivertype.DriverType) error {
	// If set to true, then we need to overwrite the driver type.
	var overwrite bool
	var err error
	if cl != nil {
		if overwrite, err = o.IsRunningInDriverModeK8S(ctx, cl); err != nil {
			return err
		}
	} else {
		if overwrite, err = o.IsRunningInDriverModeHost(); err != nil {
			return err
		}
	}
	if overwrite {
		o.Printer.Logger.Info("Committing driver config to specialized configuration file under",
			o.Printer.Logger.Args("directory", filepath.Join(o.configDir, "config.d")))
		return overwriteDriverType(o.configDir, driverType)
	}

	o.Printer.Logger.Info("Falco is not configured to run with a driver, no need to set driver type.")
	return nil
}

func setupClient(kubeconfig string) (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error

	// Create the rest config.
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}

	// Create the clientset.
	return kubernetes.NewForConfig(cfg)
}

func overwriteDriverType(configDir string, driverType drivertype.DriverType) error {
	var falcoConfig falcoCfg

	configDir = filepath.Join(configDir, "config.d")
	// First thing, check if config.d folder exists in the configuration directory.
	_, err := os.Stat(configDir)
	if os.IsNotExist(err) {
		// Create it.
		// #nosec G301 -- under /etc we want 755 permissions
		if err := os.MkdirAll(configDir, 0o755); err != nil {
			return fmt.Errorf("unable to create directory %s: %w", configDir, err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}

	falcoConfig.Engine.Kind = driverType.String()
	engineKind, err := yaml.Marshal(falcoConfig)
	if err != nil {
		return fmt.Errorf("unable to marshal falco config: %w", err)
	}

	// Write the engine configuration to a specialized config file.
	// #nosec G306 //under /etc we want 644 permissions
	if err := os.WriteFile(filepath.Join(configDir, falcoDriverConfigFile), engineKind, 0o644); err != nil {
		return fmt.Errorf("unable to persist engine kind to filesystem: %w", err)
	}

	return nil
}
