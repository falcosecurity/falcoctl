package cmd

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"github.com/spf13/cobra"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

//Default version if tag not available
var (
	Version string = "Not Available"
)

//Getting the latest GitHub Version from tag
func getVersion() string {
	cmd := exec.Command("git", "describe", "--abbrev=0", "--tags")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return Version
	}
	version := strings.Split(out.String(), "-")
	return strings.Trim(version[len(version)-1],"\n")
}

//Command to print version
func MakeVersion(streams genericclioptions.IOStreams) *cobra.Command {
	var cmd = &cobra.Command{
		Use:          "version",
		Short:        "Print the version",
		Example:      `falcoctl version`,
		SilenceUsage: false,
	}

	cmd.Run = func(cmd *cobra.Command, args []string) {
		Version = getVersion()
                fmt.Println("Version:", Version)
	}

	return cmd
}

