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

package utils

import (
	"fmt"
	"path/filepath"

	"github.com/falcosecurity/falcoctl/pkg/index"
)

// Indexes returns the merge of all configured indexes.
func Indexes(indexConfig *index.Config, path string) (*index.MergedIndexes, error) {
	var allIndexes []*index.Index

	for _, indexConfigEntry := range indexConfig.Configs {
		nameYaml := fmt.Sprintf("%s%s", indexConfigEntry.Name, ".yaml")
		i := index.New(indexConfigEntry.Name)
		err := i.Read(filepath.Join(path, nameYaml))
		if err != nil {
			return nil, fmt.Errorf("cannot load index %s: %w", i.Name, err)
		}
		allIndexes = append(allIndexes, i)
	}

	mergedIndexes := index.NewMergedIndexes()
	mergedIndexes.Merge(allIndexes...)

	return mergedIndexes, nil
}
