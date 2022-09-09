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

	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
)

type logoutOptions struct {
	*commonoptions.CommonOptions
	hostname string
}

// Validate validates the `list` command options.
func (o *logoutOptions) Validate(args []string) error {
	if len(args) != 0 {
		o.hostname = args[0]
	} else {
		o.hostname = oci.DefaultRegistry
	}
	return nil
}

// NewLogoutCmd returns the logout command.
func NewLogoutCmd(opt *commonoptions.CommonOptions) *cobra.Command {
	o := logoutOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "logout hostname",
		DisableFlagsInUseLine: true,
		Short:                 "Logout from an OCI registry",
		Long:                  "Logout from an OCI registry",
		Args:                  cobra.MaximumNArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.Validate(args))
		},
		Run: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.RunLogout(args))
		},
	}

	return cmd
}

func (o *logoutOptions) RunLogout(args []string) error {
	err := authn.Logout(o.hostname)
	if err != nil {
		return err
	}

	o.Printer.DefaultText.Println("Logout succeeded")
	return nil
}
