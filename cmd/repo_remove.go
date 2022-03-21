package cmd

import (
	"fmt"
	"github.com/falcosecurity/falcoctl/cmd/internal/validate"
	"github.com/falcosecurity/falcoctl/pkg/repo"
	"github.com/go-playground/validator/v10"
	"github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
)

// Defaults
const ()

var _ CommandOptions = &RepoRemoveOptions{}

// RepoRemoveOption represents the `repo remove` command options
type RepoRemoveOptions struct {
	RemoveAll bool
}

// AddFlags adds flag to c
func (o *RepoRemoveOptions) AddFlags(c *cobra.Command) {
	flags := c.Flags()
	flags.BoolVarP(&o.RemoveAll, "all", "a", o.RemoveAll, "Remove all repositories from local cache")
}

// Validate validates the `repo remove` command options
func (o *RepoRemoveOptions) Validate(c *cobra.Command, args []string) error {
	if err := validate.V.Struct(o); err != nil {
		return err.(validator.ValidationErrors)
	}
	return nil
}

// NewRepoRemoveOptions instantiates the `repo remove` command options
func NewRepoRemoveOptions() *RepoRemoveOptions {
	return &RepoRemoveOptions{
		RemoveAll: false,
	}
}

func NewRepoRemoveCmd(options CommandOptions) *cobra.Command {
	o := options.(*RepoOptions)

	cmd := &cobra.Command{
		Use:                   "remove",
		DisableFlagsInUseLine: true,
		Short:                 "Remove an artifact repository from the falcotl cache",
		Long:                  "Remove an artifact repository from the falcotl cache",
		PreRunE:               o.Validate,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !o.RemoveAll && len(args) == 0 {
				return fmt.Errorf("please provide one repository name or --all/-a flag")
			}
			home, err := homedir.Dir()
			if err != nil {
				logger.WithError(err).Fatal("error getting the home directory")
			}
			// HOME/.falcoctl/sources.yaml
			rfilepath := filepath.Join(home, o.RepoPath, o.RepoFile)
			// HOME/.falcoctl
			ridxpath := filepath.Join(home, o.RepoPath)

			if o.RemoveAll {
				err = repo.RemoveAll(rfilepath, ridxpath)
				if err != nil {
					return err
				}
				return nil
			}

			r, err := repo.LoadRepos(rfilepath)
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				} else {
					logger.Fatal(err.Error())
					return err
				}
			}
			err = r.RemoveRepo(args[0], ridxpath)
			if err != nil {
				logger.Fatal(err.Error())
				return err
			}
			err = repo.WriteRepos(rfilepath, r)
			if err != nil {
				logger.Fatal(err.Error())
				return err
			}
			return nil
		},
	}
	o.RepoRemoveOptions.AddFlags(cmd)
	return cmd
}
