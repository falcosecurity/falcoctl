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

package utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplaceTextInFile(t *testing.T) {
	tests := []struct {
		fileContent         string
		searchFor           string
		replacementText     string
		n                   int
		expectedFileContent string
	}{
		{
			fileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
`,
			searchFor:       "test1: 0",
			replacementText: "test1: 1",
			n:               1,
			expectedFileContent: `
foo:
  bar:
    - test1: 1
    - test2: 0
`,
		},
		// text not found
		{
			fileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
`,
			searchFor:       "test3: 0",
			replacementText: "test3: 1",
			n:               1,
			expectedFileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
`,
		},
		// N == 0 -> no replacements
		{
			fileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
`,
			searchFor:       "test1: 0",
			replacementText: "test1: 1",
			n:               0,
			expectedFileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
`,
		},
		// multiple replacements
		{
			fileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
    - test3: 0
`,
			searchFor:       "test",
			replacementText: "testFoo",
			n:               -1,
			expectedFileContent: `
foo:
  bar:
    - testFoo1: 0
    - testFoo2: 0
    - testFoo3: 0
`,
		},
	}

	file, err := os.Create("test.txt")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = file.Close()
		_ = os.Remove("test.txt")
	})

	for _, test := range tests {
		// Truncate and seek at beginning
		err = file.Truncate(0)
		require.NoError(t, err)
		_, err = file.Seek(0, 0)
		require.NoError(t, err)

		_, err = file.WriteString(test.fileContent)
		require.NoError(t, err)

		err = ReplaceTextInFile(file.Name(), test.searchFor, test.replacementText, test.n)
		require.NoError(t, err)

		content, err := os.ReadFile(file.Name())
		require.NoError(t, err)

		assert.Equal(t, test.expectedFileContent, string(content))
	}
}

func TestReplaceLineInFile(t *testing.T) {
	tests := []struct {
		fileContent         string
		searchFor           string
		replacementLine     string
		n                   int
		expectedFileContent string
	}{
		{
			fileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
`,
			searchFor:       "test1",
			replacementLine: "test1: 1",
			n:               1,
			expectedFileContent: `
foo:
  bar:
test1: 1
    - test2: 0
`,
		},
		// text not found
		{
			fileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
`,
			searchFor:       "test3",
			replacementLine: "test3: 1",
			n:               1,
			expectedFileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
`,
		},
		// N == 0 -> no replacements
		{
			fileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
`,
			searchFor:       "test1",
			replacementLine: "test1: 1",
			n:               0,
			expectedFileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
`,
		},
		// multiple replacements
		{
			fileContent: `
foo:
  bar:
    - test1: 0
    - test2: 0
    - test3: 0
`,
			searchFor:       "test",
			replacementLine: "testFoo",
			n:               -1,
			expectedFileContent: `
foo:
  bar:
testFoo
testFoo
testFoo
`,
		},
	}

	file, err := os.Create("test.txt")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = file.Close()
		_ = os.Remove("test.txt")
	})

	for _, test := range tests {
		// Truncate and seek at beginning
		err = file.Truncate(0)
		require.NoError(t, err)
		_, err = file.Seek(0, 0)
		require.NoError(t, err)

		_, err = file.WriteString(test.fileContent)
		require.NoError(t, err)

		err = ReplaceLineInFile(file.Name(), test.searchFor, test.replacementLine, test.n)
		require.NoError(t, err)

		content, err := os.ReadFile(file.Name())
		require.NoError(t, err)

		assert.Equal(t, test.expectedFileContent, string(content))
	}
}
