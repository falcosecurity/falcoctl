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
	"github.com/spf13/viper"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

const (
	DefaultCertsCountry = "US"
	DefaultCertsOrg     = "falcosecurity"
	DefaultCertsName    = "localhost"
	DefaultCertsPath    = "/etc/falco/certs"
	DefaultCertsDays    = 365
)

// TLSOptions represents the `install tls` command options
type TLSOptions struct {
	genericclioptions.IOStreams
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
func NewTLSOptions(streams genericclioptions.IOStreams) CommandOptions {
	o := &TLSOptions{
		IOStreams: streams,
	}

	// Fallback to default only when also env variable is missing
	// FALCOCTL_COUNTRY env var
	o.country = viper.GetString("country")
	if len(o.country) == 0 {
		o.country = DefaultCertsCountry
	}
	// FALCOCTL_ORG env var
	o.org = viper.GetString("org")
	if len(o.org) == 0 {
		o.org = DefaultCertsOrg
	}
	// FALCOCTL_NAME env var
	o.name = viper.GetString("name")
	if len(o.name) == 0 {
		o.name = DefaultCertsName
	}
	// FALCOCTL_DAYS env var
	o.path = viper.GetString("days")
	if len(o.path) == 0 {
		o.days = DefaultCertsDays
	}
	// FALCOCTL_PATH env var
	o.path = viper.GetString("path")
	if len(o.path) == 0 {
		o.path = DefaultCertsPath
	}

	return o
}

// InstallTLS creates the `install tls` command
func InstallTLS(streams genericclioptions.IOStreams) *cobra.Command {
	o := NewTLSOptions(streams).(*TLSOptions)

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

	cmd.Flags().StringVarP(&o.country, "country", "c", o.country, "The country to self sign the TLS cert with")
	cmd.Flags().StringVarP(&o.org, "org", "o", o.org, "The org to self sign the TLS cert with")
	cmd.Flags().StringVarP(&o.name, "name", "n", o.name, "The name to self sign the TLS cert with")
	cmd.Flags().IntVarP(&o.days, "days", "d", o.days, "The number of days to make self signed TLS cert valid for")
	cmd.Flags().StringVarP(&o.path, "path", "p", o.path, "The path to write the TLS cert to")

	return cmd
}
