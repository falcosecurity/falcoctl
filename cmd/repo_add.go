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

var _ CommandOptions = &RepoAddOptions{}

// RepoAddOption represents the `repo add` command options
type RepoAddOptions struct {
	RepoPath string
	RepoFile string
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
	return &RepoAddOptions{
		RepoPath: DefaultRepoPath,
		RepoFile: DefaultRepoFile,
	}
}

func NewRepoAddCmd(options CommandOptions) *cobra.Command {
	o := options.(*RepoAddOptions)

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
	o.AddFlags(cmd)
	return cmd
}
