package cmd

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/acarl005/stripansi"
	"gotest.tools/assert"
)

type expect struct {
	err string
	out string
}

type testCase struct {
	descr  string
	env    map[string]string
	args   []string
	expect expect
}

var tests = []testCase{
	{
		descr: "no-args-no-flags",
		args:  []string{},
		expect: expect{
			out: "testdata/noargsnoflags.txt",
		},
	},
	{
		descr: "wrong-flag",
		args:  []string{"--wrong"},
		expect: expect{
			out: "testdata/wrongflag.txt",
			err: "unknown flag: --wrong",
		},
	},
	{
		args: []string{"help"},
		expect: expect{
			out: "testdata/help.txt",
		},
	},
	{
		descr: "help-flag",
		args:  []string{"--help"},
		expect: expect{
			out: "testdata/help.txt",
		},
	},
}

func run(t *testing.T, test testCase) {
	// Setup
	c := New(nil)
	o := bytes.NewBufferString("")
	c.SetOut(o)
	c.SetErr(o)

	// test.args = append(test.args, "--dryrun") // todo > add dry run flag

	c.SetArgs(test.args)
	for k, v := range test.env {
		if err := os.Setenv(k, v); err != nil {
			t.Fatalf("error setting env variables: %v", err)
		}
	}
	// Test
	err := c.Execute()
	if err != nil {
		if test.expect.err == "" {
			t.Fatalf("error executing CLI: %v", err)
		} else {
			assert.Error(t, err, test.expect.err)
		}
	}

	out, err := ioutil.ReadAll(o)
	if err != nil {
		t.Fatalf("error reading CLI output: %v", err)
	}
	res := stripansi.Strip(string(out))
	assert.Equal(t, test.expect.out, res)
	// Teardown
	for k := range test.env {
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("error tearing down: %v", err)
		}
	}
}

func TestCLI(t *testing.T) {
	for _, test := range tests {
		descr := test.descr
		if descr == "" {
			if test.expect.out == "" {
				t.Fatal("malformed test case: missing both descr and expect.out fields")
			}
			test.descr = strings.TrimSuffix(filepath.Base(test.expect.out), ".txt")
		}
		if test.expect.out != "" {
			out, err := ioutil.ReadFile(test.expect.out)
			if err != nil {
				t.Fatalf("output fixture not found: %v", err)
			}
			test.expect.out = string(out)
		}

		t.Run(test.descr, func(t *testing.T) {
			run(t, test)
		})
	}
}
