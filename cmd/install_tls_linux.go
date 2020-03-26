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

// Defaults
const (
	DefaultCertsCountry = "US"
	DefaultCertsOrg     = "falcosecurity"
	DefaultCertsName    = "localhost"
	DefaultCertsPath    = "/etc/falco/certs"
	DefaultCertsDays    = 365
)

// TLSOptions represents the `install tls` command options
type TLSOptions struct {
	country string
	org     string
	name    string
	path    string
	days    int
}

// Validate validates the `install probe` command options
func (o TLSOptions) Validate(c *cobra.Command, args []string) error {
	// todo > validate path exists and is writable here
	return nil
}

// NewTLSOptions instantiates the `install tls` command options
func NewTLSOptions() CommandOptions {
	return &TLSOptions{
		country: DefaultCertsCountry,
		org:     DefaultCertsCountry,
		name:    DefaultCertsName,
		days:    DefaultCertsDays,
		path:    DefaultCertsPath,
	}
}

// InstallTLS creates the `install tls` command
func InstallTLS(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewTLSOptions().(*TLSOptions)

	cmd := &cobra.Command{
		Use:                   "tls",
		DisableFlagsInUseLine: true,
		Short:                 "Generate and install TLS material to be used with the Falco gRPC server",
		Long: `Falco gRPC server runs with mutually encrypted TLS by default.

This command is a convenience to not only generate the TLS material, but also drop it off on the local filesystem.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			g := tls.GRPCTLSGenerator(o.country, o.org, o.name, o.days)
			err := g.Generate()
			if err != nil {
				logger.Critical(err.Error())
				return err
			}
			err = g.FlushToDisk(o.path)
			if err != nil {
				logger.Critical(err.Error())
				return err
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&o.country, "country", "c", o.country, "The country to self sign the TLS cert with")
	flags.StringVarP(&o.org, "org", "o", o.org, "The org to self sign the TLS cert with")
	flags.StringVarP(&o.name, "name", "n", o.name, "The name to self sign the TLS cert with")
	flags.IntVarP(&o.days, "days", "d", o.days, "The number of days to make self signed TLS cert valid for")
	flags.StringVarP(&o.path, "path", "p", o.path, "The path to write the TLS cert to")

	return cmd
}
