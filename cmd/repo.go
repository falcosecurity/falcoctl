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
	*RepoRemoveOptions
	RepoPath string
	RepoFile string
}

// Validate validates the `install` command options
func (o *RepoOptions) Validate(c *cobra.Command, args []string) error {
	//TODO
	return nil
}

func (o *RepoOptions) AddFlags(c *cobra.Command) {

}

// NewRepoOptions instantiates the `repo` command options
func NewRepoOptions() CommandOptions {
	return &RepoOptions{
		RepoAddOptions:    NewRepoAddOptions(),
		RepoRemoveOptions: NewRepoRemoveOptions(),
		RepoPath:          DefaultRepoPath,
		RepoFile:          DefaultRepoFile,
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

	cmd.AddCommand(NewRepoAddCmd(o))
	cmd.AddCommand(NewRepoRemoveCmd(o))

	return cmd
}
