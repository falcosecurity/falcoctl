package cmd

import "github.com/spf13/cobra"

//Defaults
const (
	DefaultRepoPath = ".falcoctl"
	DefaultRepoFile = "sources.yaml"
)

// RepoOptions represents the install command options
type RepoOptions struct {
	*RepoAddOptions
}

// Validate validates the `install` command options
func (o *RepoOptions) Validate(c *cobra.Command, args []string) error {
	//TODO
	return nil
}

// NewRepoOptions instantiates the `repo` command options
func NewRepoOptions() CommandOptions {
	return &RepoOptions{
		RepoAddOptions: NewRepoAddOptions(),
	}
}

func NewRepoCmd(options CommandOptions) *cobra.Command {
	o := options.(*RepoOptions)
	cmd := &cobra.Command{
		Use:                   "repo",
		DisableFlagsInUseLine: true,
		Short:                 "Manage artifact repositories",
		Long:                  "Manage artifact repositories",
	}

	cmd.AddCommand(NewRepoAddCmd(o.RepoAddOptions))

	return cmd
}
