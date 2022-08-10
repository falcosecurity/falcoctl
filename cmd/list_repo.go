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
	"text/tabwriter"

	"github.com/go-playground/validator/v10"
	"github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/falcosecurity/falcoctl/cmd/internal/validate"
	"github.com/falcosecurity/falcoctl/pkg/repo"
)

// Defaults
const ()

var _ CommandOptions = &ListRepoOptions{}

// ListRepoOption represents the `list repo` command options
type ListRepoOptions struct {
}

// AddFlags adds flag to c
func (o *ListRepoOptions) AddFlags(c *cobra.Command) {
}

// Validate validates the `list repo` command options
func (o *ListRepoOptions) Validate(c *cobra.Command, args []string) error {
	if err := validate.V.Struct(o); err != nil {
		return err.(validator.ValidationErrors)
	}
	return nil
}

// NewRepoAddOptions instantiates the `list repo` command options
func NewListRepoOptions() *ListRepoOptions {
	return &ListRepoOptions{}
}

func NewListRepoCmd(options CommandOptions) *cobra.Command {
	o := options.(*ListOptions)

	cmd := &cobra.Command{
		Use:                   "repo",
		DisableFlagsInUseLine: true,
		Short:                 "Print artifact repositories managed by falcoctl",
		Long:                  "Print artifact repositories managed by falcoctl",
		PreRunE:               o.Validate,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return fmt.Errorf("expected 0 arguments")
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
			w := new(tabwriter.Writer)
			w.Init(os.Stdout, 8, 8, 0, '\t', 0)
			defer w.Flush()
			fmt.Fprintf(w, "%s\t%s\t%s\t", "NAME", "URL", "UPDATED")
			for _, k := range r.Sources {
				fmt.Fprintf(w, "\n%s\t%s\t%s\t", k.Name, k.Url, k.Date)
			}
			fmt.Fprintf(w, "\n")
			return nil
		},
	}
	o.ListRepoOptions.AddFlags(cmd)
	return cmd
}
