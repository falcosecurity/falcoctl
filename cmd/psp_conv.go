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
	"github.com/falcosecurity/falcoctl/pkg/kubernetes/factory"
	"github.com/falcosecurity/falcoctl/pkg/psp_conv"
	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
	"io/ioutil"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"os"
)

// Represents options for PSP->Rules Conversion
type PspRulesConvOptions struct {
	pspPath string
	rulesPath string
}

// Validate options to psp_conv command
func (o PspRulesConvOptions) Validate(c *cobra.Command, args []string) error {
	if o.pspPath == "" {
		return fmt.Errorf("--pspPath must be provided")
	}

	if o.rulesPath == "" {
		return fmt.Errorf("--rulesPath must be provided")
	}

	return nil
}

func NewPspRulesConvOptions() CommandOptions {
	return &PspRulesConvOptions{
		pspPath: "",
		rulesPath: "./psp_falco_rules.yaml",
	}
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
		return fmt.Errorf("Could not open pspFile for reading: %v")
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

func NewPspRulesConvCommand(streams genericclioptions.IOStreams, f factory.Factory) *cobra.Command {

	o := NewPspRulesConvOptions().(*PspRulesConvOptions)

	cmd := &cobra.Command{
		Use:                   "psp_conv",
		Short:                 "Convert a PSP to a set of Falco Rules",
		Long:                  `Convert a K8s Pod Security Policy (PSP), provided via the --pspPath argument, to a set of falco rules that can evaluate the conditions in the PSP. The resulting rules are written to the file provided by the --rulesPath argument`,
		Run: func(cmd *cobra.Command, args []string) {
			err := convertPspFalcoRules(o.pspPath, o.rulesPath); if err != nil {
				logger.Critical("Could not convert PSP to Falco Rules: %v", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&o.pspPath, "PSP Path", "P", o.pspPath, "Path to PSP as yaml file")
	cmd.Flags().StringVarP(&o.rulesPath, "Rules Path", "R", o.rulesPath, "Write converted rules to this file")

	return cmd
}
