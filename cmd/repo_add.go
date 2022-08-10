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
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-playground/validator/v10"
	"github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/cmd/internal/validate"
	"github.com/falcosecurity/falcoctl/pkg/repo"
)

// Defaults
const ()

var _ CommandOptions = &RepoAddOptions{}

// RepoAddOption represents the `repo add` command options
type RepoAddOptions struct {
}

// AddFlags adds flag to c
func (o *RepoAddOptions) AddFlags(c *cobra.Command) {
}

// Validate validates the `repo add` command options
func (o *RepoAddOptions) Validate(c *cobra.Command, args []string) error {
	if err := validate.V.Struct(o); err != nil {
		return err.(validator.ValidationErrors)
	}
	return nil
}

// NewRepoAddOptions instantiates the `search registry` command options
func NewRepoAddOptions() *RepoAddOptions {
	return &RepoAddOptions{}
}

func NewRepoAddCmd(options CommandOptions) *cobra.Command {
	o := options.(*RepoOptions)

	cmd := &cobra.Command{
		Use:                   "add",
		DisableFlagsInUseLine: true,
		Short:                 "Adds an artifact repository to the falcoctl cache",
		Long:                  "Adds an artifact repository to the falcoctl cache",
		PreRunE:               o.Validate,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 2 {
				return fmt.Errorf("please provide name and URL of the repository to add")
			}
			home, err := homedir.Dir()
			if err != nil {
				logger.WithError(err).Fatal("error getting the home directory")
			}
			// HOME/.falcoctl/sources.yaml
			path := filepath.Join(home, o.RepoPath, o.RepoFile)
			r, err := repo.LoadRepos(path)
			if err != nil {
				if os.IsNotExist(err) {
					r = &repo.RepoList{}
				} else {

					logger.Fatal(err.Error())
					return err
				}
			}
			err = r.AddRepo(args[0], args[1])
			if err != nil {
				logger.Fatal(err.Error())
				return err
			}
			err = repo.WriteRepos(path, r)
			if err != nil {
				logger.Fatal(err.Error())
				return err
			}
			return nil
		},
	}
	o.RepoAddOptions.AddFlags(cmd)
	return cmd
}
