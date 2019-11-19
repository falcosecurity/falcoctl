/*
Copyright © 2019 The Falco Authors.

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
	"github.com/falcosecurity/falcoctl/pkg/tls"
	"github.com/kris-nova/logger"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// TLSInstallOptions represents the `install tls` command options
type TLSInstallOptions struct {
	genericclioptions.IOStreams
	country string
	org     string
	name    string
	path    string
}

// Validate validates the `install probe` command options
func (o TLSInstallOptions) Validate(c *cobra.Command, args []string) error {
	return nil
}

// NewTLSInstallOptions instantiates the `install tls` command options
func NewTLSInstallOptions(streams genericclioptions.IOStreams) CommandOptions {
	o := &TLSInstallOptions{
		IOStreams: streams,
	}
	return o
}

// NewTLSInstallCommand creates the `install tls` command
func NewTLSInstallCommand(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewTLSInstallOptions(streams).(*TLSInstallOptions)

	cmd := &cobra.Command{
		Use:                   "tls",
		DisableFlagsInUseLine: true,
		Short:                 "Generate and install TLS material to be used with the Falco gRPC server",
		Long: `Falco runs with mutually encrypted TLS by default. 

This command is a convenience to not only generate the TLS material - but also drop it off on the local filesystem.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			g := tls.NewGRPCTLSGenerator(o.country, o.org, o.name)
			err := g.Generate()
			if err != nil {
				logger.Critical(err.Error())
			}
			err = g.FlushToDisk(o.path)
			if err != nil {
				logger.Critical(err.Error())
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&o.country, "country", "c", "US", "The country to self sign the TLS cert with")
	cmd.Flags().StringVarP(&o.org, "org", "o", "SysDig", "The org to self sign the TLS cert with")
	cmd.Flags().StringVarP(&o.name, "name", "n", "Default", "The name to self sign the TLS cert with")
	cmd.Flags().StringVarP(&o.path, "path", "p", "/etc/falco/certs/", "The path to write the TLS cert to")

	return cmd
}
