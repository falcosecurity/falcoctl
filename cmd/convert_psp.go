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
	"io"
	"os"

	"io/ioutil"

	converter "github.com/falcosecurity/falcoctl/pkg/converter/psp"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// PspConvertOptions represents options for PSP to Falco rules conversion
type PspConvertOptions struct {
	pspPath   string
	rulesPath string
}

func (o *PspConvertOptions) AddFlags(c *cobra.Command) {
	c.Flags().StringVarP(&o.pspPath, "psp-path", "P", o.pspPath, "Path to PSP as YAML file")
	c.Flags().StringVarP(&o.rulesPath, "rules-path", "R", o.rulesPath, "Write converted rules to this file")
}

// Validate options to psp_conv command
func (o PspConvertOptions) Validate(c *cobra.Command, args []string) error {
	if o.pspPath == "" {
		return fmt.Errorf("--psp-path must be provided")
	}

	if o.rulesPath == "" {
		return fmt.Errorf("--rules-path must be provided")
	}

	return nil
}

// NewPspConvertOptions instantiates PspConvertOptions
func NewPspConvertOptions() *PspConvertOptions {
	return &PspConvertOptions{
		rulesPath: "./psp_falco_rules.yaml", // default
	}
}

func convertPspFalcoRules(pspPath string, rulesPath string) error {
	pspFile, err := os.Open(pspPath)
	if err != nil {
		return fmt.Errorf("Could not open PSP file for reading: %s", pspPath)
	}
	defer pspFile.Close()

	logger.Debugf("Reading PSP from %s", pspPath)

	psp, err := ioutil.ReadAll(pspFile)
	if err != nil && err != io.EOF {
		return fmt.Errorf("Could not read PSP file: %s", pspPath)
	}

	conv, err := converter.NewConverter(logger.Debugf, logger.Infof, logger.Errorf)
	if err != nil {
		return fmt.Errorf("Could not create converter: %v", err)
	}

	rules, err := conv.GenerateRules("", string(psp), []string{})
	if err != nil {
		return fmt.Errorf("Could not convert psp file to falco rules: %v", err)
	}

	if err = ioutil.WriteFile(rulesPath, []byte(rules), 0644); err != nil {
		return fmt.Errorf("Could not write rules to: %s", rulesPath)
	}

	logger.Debugf("Wrote rules to %s", rulesPath)

	return nil
}

// NewPspConvert instantiates the `convert psp` command
func NewPspConvertCmd(options CommandOptions) *cobra.Command {
	o := options.(*PspConvertOptions)

	cmd := &cobra.Command{
		Use:   "psp",
		Short: "Convert a PSP to a set of Falco Rules",
		Long: `Convert a K8s Pod Security Policy (PSP), provided via the --psp-path argument, to a set of Falco rules that can evaluate the conditions in the PSP.
The resulting rules are written to the file provided by the --rules-path argument`,
		PreRunE: o.Validate,
		RunE: func(cmd *cobra.Command, args []string) error {
			return convertPspFalcoRules(o.pspPath, o.rulesPath)
		},
	}

	o.AddFlags(cmd)

	return cmd
}
