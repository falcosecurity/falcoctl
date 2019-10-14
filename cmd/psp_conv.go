/*
Copyright © 2019 The Falco Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"fmt"
	"os"

	converter "github.com/falcosecurity/falcoctl/pkg/converter/psp"
	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io/ioutil"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// PspRulesConvOptions represents options for PSP to Falco rules conversion
type PspRulesConvOptions struct {
	genericclioptions.IOStreams

	pspPath   string
	rulesPath string
}

// Validate options to psp_conv command
func (o PspRulesConvOptions) Validate(c *cobra.Command, args []string) error {
	if o.pspPath == "" {
		return fmt.Errorf("--psp-path must be provided")
	}

	if o.rulesPath == "" {
		return fmt.Errorf("--rules-path must be provided")
	}

	return nil
}

// NewPspRulesConvOptions instantiates PspRulesConvOptions
func NewPspRulesConvOptions(streams genericclioptions.IOStreams) CommandOptions {
	o := &PspRulesConvOptions{
		IOStreams: streams,
	}
	o.pspPath = viper.GetString("psp-path")     // FALCOCTL_PSP_PATH env var
	o.rulesPath = viper.GetString("rules-path") // FALCOCTL_RULES_PATH env var
	if len(o.rulesPath) == 0 {
		o.rulesPath = "./psp_falco_rules.yaml" // default
	}
	return o
}

func debugLog(format string, args ...interface{}) {
	logger.Debug(format, args)
}

func infoLog(format string, args ...interface{}) {
	logger.Info(format, args)
}

func errorLog(format string, args ...interface{}) {
	logger.Critical(format, args)
}

func convertPspFalcoRules(pspPath string, rulesPath string) error {
	pspFile, err := os.Open(pspPath)
	if err != nil {
		return fmt.Errorf("Could not open PSP file for reading: %s", pspPath)
	}
	defer pspFile.Close()

	logger.Debug("Reading PSP from %s", pspPath)

	psp, err := ioutil.ReadAll(pspFile)

	conv, err := converter.NewConverter(debugLog, infoLog, errorLog)
	if err != nil {
		return fmt.Errorf("Could not create converter: %v", err)
	}

	rules, err := conv.GenerateRules(string(psp))
	if err != nil {
		return fmt.Errorf("Could not convert psp file to falco rules: %v", err)
	}

	err = ioutil.WriteFile(rulesPath, []byte(rules), 0644)

	logger.Debug("Wrote rules to %s", rulesPath)

	return nil
}

// NewPspRulesConvCommand instantiates the `convert psp` command
func NewPspRulesConvCommand(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewPspRulesConvOptions(streams).(*PspRulesConvOptions)

	cmd := &cobra.Command{
		Use:   "psp",
		Short: "Convert a PSP to a set of Falco Rules",
		Long: `Convert a K8s Pod Security Policy (PSP), provided via the --psp-path argument, to a set of Falco rules that can evaluate the conditions in the PSP.
The resulting rules are written to the file provided by the --rules-path argument`,
		PreRun: func(cmd *cobra.Command, args []string) {
			if err := o.Validate(cmd, args); err != nil {
				logger.Critical("%s", err)
				os.Exit(1)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			if err := convertPspFalcoRules(o.pspPath, o.rulesPath); err != nil {
				logger.Critical("%s", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&o.pspPath, "psp-path", "P", o.pspPath, "Path to PSP as YAML file")
	cmd.Flags().StringVarP(&o.rulesPath, "rules-path", "R", o.rulesPath, "Write converted rules to this file")

	return cmd
}
