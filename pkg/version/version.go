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

package version

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	commonoptions "github.com/falcosecurity/falcoctl/pkg/options"
	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	yamlFormat = "yaml"
	jsonFormat = "json"
)

var (
	// Semantic version that refers to ghe version (git tag) of Falcoctl that is released.
	// For prerelease versions, the build metadata on the
	// semantic version is a git hash some as the gitCommit
	// NOTE: The $Format strings are replaced during 'git archive' thanks to the
	// companion .gitattributes file containing 'export-subst' in this same
	// directory.  See also https://git-scm.com/docs/gitattributes
	semVersion = "v0.0.0-master+$Format:%H$"

	// sha1 from git, output of $(git rev-parse HEAD).
	gitCommit = "$Format:%H$"

	// build date in ISO8601 format, output of $(date -u +'%Y-%m-%dT%H:%M:%SZ').
	buildDate = "1970-01-01T00:00:00Z"
)

type options struct {
	*commonoptions.ConfigOptions
	Output string
}

var errOutputFlag = errors.New("--output must be 'yaml' or 'json'")

type version struct {
	SemVersion string `json:"semVersion"`
	GitCommit  string `json:"gitCommit"`
	BuildDate  string `json:"buildDate"`
	GoVersion  string `json:"goVersion"`
	Compiler   string `json:"compiler"`
	Platform   string `json:"platform"`
}

func newVersion() version {
	// These variables usually come from -ldflags settings and in their
	// absence fallback to the ones defined in the var section.
	return version{
		SemVersion: semVersion,
		GitCommit:  gitCommit,
		BuildDate:  buildDate,
		GoVersion:  runtime.Version(),
		Compiler:   runtime.Compiler,
		Platform:   fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// NewVersionCmd returns the version command.
func NewVersionCmd(opt *commonoptions.ConfigOptions) *cobra.Command {
	o := options{
		ConfigOptions: opt,
	}

	v := newVersion()
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the falcoctl version information",
		Long:  "Print the falcoctl version information",
		Args:  cobra.NoArgs,
		PreRun: func(cmd *cobra.Command, args []string) {
			o.Printer.CheckErr(o.validate())
		},
		Run: func(cmd *cobra.Command, args []string) {
			output.ExitOnErr(o.Run(&v))
		},
	}
	cmd.Flags().StringVarP(&o.Output, "output", "o", "", "One of 'yaml' or 'json'")

	return cmd
}

func (o *options) validate() error {
	if o.Output != "" && o.Output != yamlFormat && o.Output != jsonFormat {
		return errOutputFlag
	}

	return nil
}

// Run executes the business logic for the version command.
func (o *options) Run(v *version) error {
	switch o.Output {
	case "":
		o.Printer.DefaultText.Printf("Client Version: %s\n", v.SemVersion)
	case yamlFormat:
		marshaled, err := yaml.Marshal(v)
		if err != nil {
			o.Printer.Error.Println(err.Error())
			return err
		}
		o.Printer.DefaultText.Printf("%s:\n%s\n", "Client Version", string(marshaled))
	case jsonFormat:
		marshaled, err := json.MarshalIndent(v, "", "   ")
		if err != nil {
			o.Printer.Error.Println(err.Error())
			return err
		}
		o.Printer.DefaultText.Printf("%s:\n%s \n", "Client Version", string(marshaled))
	default:
		// We should never hit this case.
		o.Printer.Error.Printf("options of the version command were not validated: --output=%q should have been rejected", o.Output)
		return fmt.Errorf("options of the version command were not validated: --output=%q should have been rejected", o.Output)
	}

	return nil
}
