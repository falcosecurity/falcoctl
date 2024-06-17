// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 The Falco Authors
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
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
	"oras.land/oras-go/v2/registry/remote/credentials"

	"github.com/falcosecurity/falcoctl/internal/config"
	"github.com/falcosecurity/falcoctl/internal/login/basic"
	"github.com/falcosecurity/falcoctl/pkg/oci/authn"
	"github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

type loginOptions struct {
	*options.Common
	username          string
	password          string
	passwordFromStdin bool
}

// NewBasicCmd returns the basic command.
func NewBasicCmd(ctx context.Context, opt *options.Common) *cobra.Command {
	o := loginOptions{
		Common: opt,
	}

	cmd := &cobra.Command{
		Use:                   "basic [hostname]",
		DisableFlagsInUseLine: true,
		Short:                 "Login to an OCI registry",
		Long: `Login to an OCI registry

Example - Log in with username and password from command line flags:
	falcoctl registry auth basic -u username -p password localhost:5000

Example - Login with username and password from env variables:
	FALCOCTL_REGISTRY_AUTH_BASIC_USERNAME=username FALCOCTL_REGISTRY_AUTH_BASIC_PASSWORD=password falcoctl registry auth basic localhost:5000

Example - Login with username and password from stdin:
	falcoctl registry auth basic -u username --password-stdin localhost:5000

Example - Login with username and password in an interactive prompt:
	falcoctl registry auth basic localhost:5000
`,
		Args: cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			o.username = viper.GetString("registry.auth.basic.username")
			o.password = viper.GetString("registry.auth.basic.password")
			o.passwordFromStdin = viper.GetBool("registry.auth.basic.password_stdin")

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.RunBasic(ctx, args)
		},
	}

	cmd.Flags().StringVarP(&o.username, "username", "u", "", "registry username")
	cmd.Flags().StringVarP(&o.password, "password", "p", "", "registry password")
	cmd.Flags().BoolVar(&o.passwordFromStdin, "password-stdin", false, "read password from stdin")

	_ = viper.BindPFlag("registry.auth.basic.username", cmd.Flags().Lookup("username"))
	_ = viper.BindPFlag("registry.auth.basic.password", cmd.Flags().Lookup("password"))
	_ = viper.BindPFlag("registry.auth.basic.password_stdin", cmd.Flags().Lookup("password-stdin"))

	// Bind to environment variables.
	viper.AutomaticEnv()

	return cmd
}

// RunBasic executes the business logic for the basic command.
func (o *loginOptions) RunBasic(ctx context.Context, args []string) error {
	reg := args[0]
	logger := o.Printer.Logger
	if err := getCredentials(o.Printer, o); err != nil {
		return err
	}

	// create empty client
	client := authn.NewClient()

	// create credential store
	credentialStore, err := credentials.NewStore(config.RegistryCredentialConfPath(), credentials.StoreOptions{
		AllowPlaintextPut: true,
	})
	if err != nil {
		return fmt.Errorf("unable to create new store: %w", err)
	}

	if err := basic.Login(ctx, client, credentialStore, reg, o.username, o.password); err != nil {
		return err
	}
	logger.Debug("Credentials added", logger.Args("credential store", config.RegistryCredentialConfPath()))
	logger.Info("Login succeeded", logger.Args("registry", reg, "user", o.username))

	return nil
}

// getCredentials is used to retrieve username and password from standard input.
func getCredentials(p *output.Printer, opt *loginOptions) error {
	reader := bufio.NewReader(os.Stdin)

	if opt.username == "" {
		p.DefaultText.Print(p.FormatTitleAsLoggerInfo("Enter username:"))
		username, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		opt.username = strings.TrimSpace(username)
	}

	if opt.password == "" {
		if opt.passwordFromStdin {
			password, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
			opt.password = strings.TrimSuffix(string(password), "\n")
			opt.password = strings.TrimSuffix(opt.password, "\r")
		} else {
			p.DefaultText.Print(p.FormatTitleAsLoggerInfo("Enter password: "))
			bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return err
			}

			opt.password = string(bytePassword)
		}
	}

	return nil
}
