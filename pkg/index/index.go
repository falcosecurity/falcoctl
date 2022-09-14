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

package index

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// IndexEntry describe an entry of the index stored remotely and cached locally.
type IndexEntry struct {
	Description string   `yaml:"description"`
	Home        string   `yaml:"home"`
	Keywords    []string `yaml:"keywords"`
	License     string   `yaml:"license"`
	Maintainers []struct {
		Email string `yaml:"email"`
		Name  string `yaml:"name"`
	} `yaml:"maintainers"`
	Name       string   `yaml:"name"`
	Registry   string   `yaml:"registry"`
	Repository string   `yaml:"repository"`
	Sources    []string `yaml:"sources"`
	Type       string   `yaml:"type"`
}

type Index struct {
	Name        string
	Filename    string
	config      *IndexConfig
	Entries     []*IndexEntry
	entryByName map[string]*IndexEntry
}

type MergedIndexes struct {
	Index
	indexByEntry map[*IndexEntry]*Index
}

// NewIndex loads an index from a file.
func NewIndex(path string) (*Index, error) {
	indexBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read file %s: %w", path, err)
	}

	var index Index
	if err = yaml.Unmarshal(indexBytes, &index); err != nil {
		return nil, fmt.Errorf("cannot unmarshal index: %w", err)
	}

	return &index, nil
}

// Add adds a new entry to the index or updates an existing one.
func (i *Index) Upsert(entry *IndexEntry) {
	defer func() {
		i.entryByName[entry.Name] = entry
	}()

	for k, e := range i.Entries {
		if e.Name == entry.Name {
			i.Entries[k] = entry
			return
		}
	}
	i.Entries = append(i.Entries, entry)
}

func (i *Index) Remove(entry *IndexEntry) error {
	for k, e := range i.Entries {
		if e == entry {
			i.Entries = append(i.Entries[:k], i.Entries[k+1:]...)
			delete(i.entryByName, e.Name)
			return nil
		}
	}

	return fmt.Errorf("cannot remove %s: not found", entry.Name)
}

func (i *Index) EntryByName(name string) *IndexEntry {
	return i.entryByName[name]
}

func (i *Index) Write(path string) error {
	indexBytes, err := yaml.Marshal(i.Entries)
	if err != nil {
		return fmt.Errorf("cannot marshal index: %w", err)
	}

	if err = os.WriteFile(path, indexBytes, 0600); err != nil {
		return fmt.Errorf("cannot write index to file: %w", err)
	}

	return nil
}

// Merge creates a new index considering all the indexes that are passed.
// Orders matters. Be sure to pass an ordered list of indexes. For our use case, sort by added time.
func (m *MergedIndexes) Merge(indexes ...*Index) {
	for _, index := range indexes {
		for _, indexEntry := range index.Entries {
			m.Upsert(indexEntry)
			m.indexByEntry[indexEntry] = index
		}
	}
}

func (m *MergedIndexes) SearchByKeywords(keywords ...string) {

}
