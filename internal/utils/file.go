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
	"log"
	"os"
	"path/filepath"
	"strings"
)

// ReplaceTextInFile searches for occurrences of searchFor in the file pointed by filePath,
// and substitutes the matching string with the provided one.
// At most n substitutions are made.
// If n < 0, there is no limit on the number of replacements.
func ReplaceTextInFile(filePath, searchFor, newText string, n int) error {
	return replaceInFile(filePath, searchFor, n, func(line string) string {
		return strings.Replace(line, searchFor, newText, 1)
	})
}

// ReplaceLineInFile searches for occurrences of searchFor in the file pointed by filePath,
// and substitutes the whole matching line with the provided one.
// At most n substitutions are made.
// If n < 0, there is no limit on the number of replacements.
func ReplaceLineInFile(filePath, searchFor, newLine string, n int) error {
	return replaceInFile(filePath, searchFor, n, func(_ string) string {
		return newLine
	})
}

func replaceInFile(filePath, searchFor string, n int, replacementCB func(string) string) error {
	if n == 0 {
		return nil
	}

	stat, err := os.Stat(filePath)
	if err != nil {
		return err
	}

	input, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		log.Fatalln(err)
	}

	lines := strings.Split(string(input), "\n")

	replaced := 0
	for i, line := range lines {
		if strings.Contains(line, searchFor) {
			lines[i] = replacementCB(line)
			replaced++
			if replaced == n {
				break
			}
		}
	}
	newContent := strings.Join(lines, "\n")
	return os.WriteFile(filePath, []byte(newContent), stat.Mode())
}

// FileExists checks if a file exists on disk.
func FileExists(filename string) (bool, error) {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	return !info.IsDir(), nil
}
