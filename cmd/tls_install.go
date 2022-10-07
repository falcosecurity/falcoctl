// Copyright 2022 The Falco Authors
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

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/pkg/install/tls"
)

// Defaults.
const (
	defaultCertsCountry = "US"
	defaultCertsOrg     = "falcosecurity"
	defaultCertsName    = "localhost"
	defaultCertsPath    = ""
	defaultCertsDays    = 365
)

// NewTLSInstallCmd returns the tls install command.
func NewTLSInstallCmd() *cobra.Command {
	options := tls.Options{}

	cmd := &cobra.Command{
		Use:                   "install",
		DisableFlagsInUseLine: true,
		Short:                 "Generate and install TLS material to be used with the Falco gRPC server",
		Long: `Falco gRPC server runs with mutually encrypted TLS by default.

This command is a convenience to not only generate the TLS material, but also drop it off on the local filesystem.`,
		RunE: func(c *cobra.Command, args []string) error {
			return options.Run()
		},
	}

	cmd.Flags().StringVarP(&options.Country, "country", "", defaultCertsCountry, "The country to self sign the TLS cert with")
	cmd.Flags().StringVarP(&options.Org, "org", "o", defaultCertsOrg, "The org to self sign the TLS cert with")
	cmd.Flags().StringVarP(&options.Name, "name", "n", defaultCertsName, "The name to self sign the TLS cert with")
	cmd.Flags().IntVarP(&options.Days, "days", "d", defaultCertsDays, "The number of days to make self signed TLS cert valid for")
	cmd.Flags().StringVarP(&options.Path, "path", "p", defaultCertsPath, "The path to write the TLS cert to")

	return cmd
}
