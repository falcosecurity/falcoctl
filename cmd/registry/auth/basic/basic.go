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

package basic

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/utils"
	"github.com/falcosecurity/falcoctl/pkg/oci"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	"github.com/falcosecurity/falcoctl/pkg/oci/registry"
	"github.com/falcosecurity/falcoctl/pkg/options"
)

type loginOptions struct {
	*options.CommonOptions
	hostname string
}

func (o *loginOptions) Validate(args []string) error {
	if len(args) != 0 {
		o.hostname = args[0]
	} else {
		o.hostname = oci.DefaultRegistry
	}
	return nil
}

// NewBasicCmd returns the basic command.
func NewBasicCmd(ctx context.Context, opt *options.CommonOptions) *cobra.Command {
	o := loginOptions{
		CommonOptions: opt,
	}

	cmd := &cobra.Command{
		Use:                   "basic [hostname]",
		DisableFlagsInUseLine: true,
		Short:                 "Login to an OCI registry",
		Long:                  "Login to an OCI registry to push and pull artifacts",
		Args:                  cobra.MaximumNArgs(1),
		SilenceErrors:         true,
		SilenceUsage:          true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return o.Validate(args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunBasic(ctx, args)
		},
	}

	return cmd
}

// RunBasic executes the business logic for the basic command.
func (o *loginOptions) RunBasic(ctx context.Context, args []string) error {
	var reg string

	if n := len(args); n == 1 {
		reg = args[0]
	} else {
		reg = oci.DefaultRegistry
	}

	user, token, err := utils.GetCredentials(o.Printer)
	if err != nil {
		return err
	}

	cred := &auth.Credential{
		Username: user,
		Password: token,
	}

	if err = DoLogin(ctx, reg, cred); err != nil {
		return err
	}

	currentAuths, err := config.BasicAuths()
	if err != nil {
		return fmt.Errorf("unable to get basicAuths from viper: %w", err)
	}

	for _, a := range currentAuths {
		if a.Registry == reg {
			o.Printer.Verbosef("credentials for registry %q already exists in the config file %q", reg, config.ConfigPath)
			return nil
		}
	}

	currentAuths = append(currentAuths, config.BasicAuth{
		Registry: reg,
		User:     user,
		Password: token,
	})

	if err := config.UpdateConfigFile(config.RegistryAuthBasicKey, currentAuths, o.ConfigFile); err != nil {
		return fmt.Errorf("unable to update basic auths credential list in the config file %q: %w", config.ConfigPath, err)
	}
	o.Printer.Verbosef("credentials added to config file %q", config.ConfigPath)

	o.Printer.Success.Println("Login succeeded")
	return nil
}

// DoLogin checks if passed credentials are correct and stores them.
func DoLogin(ctx context.Context, reg string, cred *auth.Credential) error {
	client := authn.NewClient(authn.WithCredentials(cred))
	r, err := registry.NewRegistry(reg, registry.WithClient(client))
	if err != nil {
		return err
	}

	if err := r.CheckConnection(ctx); err != nil {
		return fmt.Errorf("unable to connect to registry %q: %w", reg, err)
	}

	// Store validated credentials
	err = authn.Login(reg, cred.Username, cred.Password)
	if err != nil {
		return err
	}

	return nil
}
