// Copyright 2023 The Falco Authors
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
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Move moves oldPath file to to newPath file. It works also on different file system types.
func Move(oldPath, newPath string) error {
	err := os.Rename(oldPath, newPath)
	if err != nil {
		// if rename fails, just do a copy
		data, err := os.ReadFile(filepath.Clean(oldPath))
		if err != nil {
			return fmt.Errorf("unable to read file %s: %w", oldPath, err)
		}

		err = os.WriteFile(newPath, data, 0o600)
		if err != nil {
			return fmt.Errorf("unable to write to file %s: %w", newPath, err)
		}
	}

	return nil
}

// ExistsAndIsWritable checks if the directory specified by the path exists and is writable.
func ExistsAndIsWritable(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s doesn't exists", path)
	} else if err != nil {
		return err
	}

	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}

	if f, err := os.Create(filepath.Join(filepath.Clean(path), "._check_writable")); err == nil {
		if err := f.Close(); err != nil {
			return err
		}
		if err := os.Remove(f.Name()); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("%s is not writable", path)
	}

	return nil
}
