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
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Defaults
const (
	DefaultCertsCountry = "US"
	DefaultCertsOrg     = "falcosecurity"
	DefaultCertsName    = "localhost"
	DefaultCertsPath    = "/etc/falco/certs"
	DefaultCertsDays    = 365
)

var _ CommandOptions = &TLSOptions{}

// TLSOptions represents the `install tls` command options
type TLSOptions struct {
	country string
	org     string
	name    string
	path    string
	days    int
}

// AddFlags adds flag to c
func (o *TLSOptions) AddFlags(c *cobra.Command) {
	flags := c.Flags()
	flags.StringVarP(&o.country, "country", "", o.country, "The country to self sign the TLS cert with")
	flags.StringVarP(&o.org, "org", "o", o.org, "The org to self sign the TLS cert with")
	flags.StringVarP(&o.name, "name", "n", o.name, "The name to self sign the TLS cert with")
	flags.IntVarP(&o.days, "days", "d", o.days, "The number of days to make self signed TLS cert valid for")
	flags.StringVarP(&o.path, "path", "p", o.path, "The path to write the TLS cert to")
}

// Validate validates the `install probe` command options
func (o *TLSOptions) Validate(c *cobra.Command, args []string) error {
	// todo > validate path exists and is writable here
	return nil
}

// NewTLSOptions instantiates the `install tls` command options
func NewTLSOptions() *TLSOptions {
	return &TLSOptions{
		country: DefaultCertsCountry,
		org:     DefaultCertsCountry,
		name:    DefaultCertsName,
		days:    DefaultCertsDays,
		path:    DefaultCertsPath,
	}
}

// NewInstallTLS creates the `install tls` command
func NewInstallTLSCmd(options CommandOptions) *cobra.Command {
	o := options.(*TLSOptions)

	cmd := &cobra.Command{
		Use:                   "tls",
		DisableFlagsInUseLine: true,
		Short:                 "Generate and install TLS material to be used with the Falco gRPC server",
		Long: `Falco gRPC server runs with mutually encrypted TLS by default.

This command is a convenience to not only generate the TLS material, but also drop it off on the local filesystem.`,
		PreRunE: o.Validate,
		RunE: func(c *cobra.Command, args []string) error {
			g := tls.GRPCTLSGenerator(o.country, o.org, o.name, o.days)
			err := g.Generate()
			if err != nil {
				logger.Fatal(err.Error())
				return err
			}
			err = g.FlushToDisk(o.path)
			if err != nil {
				logger.Fatal(err.Error())
				return err
			}

			return nil
		},
	}

	o.AddFlags(cmd)

	return cmd
}
