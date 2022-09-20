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
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Entry describes an entry of the index stored remotely and cached locally.
type Entry struct {
	// Mandatory fields
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	Registry   string `yaml:"registry"`
	Repository string `yaml:"repository"`
	// Optional fields
	Description string   `yaml:"description"`
	Home        string   `yaml:"home"`
	Keywords    []string `yaml:"keywords"`
	License     string   `yaml:"license"`
	Maintainers []struct {
		Email string `yaml:"email"`
		Name  string `yaml:"name"`
	} `yaml:"maintainers"`
	Sources []string `yaml:"sources"`
}

// Index represents an index.
type Index struct {
	Name        string
	Entries     []*Entry
	entryByName map[string]*Entry
}

// MergedIndexes is used to aggregate all indexes and perform search operations.
type MergedIndexes struct {
	Index
	indexByEntry map[*Entry]*Index
}

// New loads an Index from a file.
func New(path, name string) (*Index, error) {
	indexBytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("cannot read file %s: %w", path, err)
	}

	var index Index
	var entries []Entry
	if err = yaml.Unmarshal(indexBytes, &entries); err != nil {
		return nil, fmt.Errorf("cannot unmarshal index: %w", err)
	}

	for k := range entries {
		index.Entries = append(index.Entries, &entries[k])
	}

	index.Name = name

	return &index, nil
}

// Upsert adds a new entry to the Index or updates an existing one.
func (i *Index) Upsert(entry *Entry) {
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

// Remove removes an entry from the Index.
func (i *Index) Remove(entry *Entry) error {
	for k, e := range i.Entries {
		if e == entry {
			i.Entries = append(i.Entries[:k], i.Entries[k+1:]...)
			delete(i.entryByName, e.Name)
			return nil
		}
	}

	return fmt.Errorf("cannot remove %s: not found", entry.Name)
}

// EntryByName returns a Entry by passing its name.
func (i *Index) EntryByName(name string) *Entry {
	return i.entryByName[name]
}

// Normalize the index to the canonical form (i.e., entries sorted by name,
// lexically byte-wise in ascending order).
//
// Since only one possible representation of a normalized index exists,
// a digest of a normalized index is suitable for integrity checking
// or similar purposes.
// Return an error if the index is not in a consistent state.
func (i *Index) Normalize() error {
	if i == nil {
		return fmt.Errorf("cannot normalize an uninitialized index")
	}

	if len(i.entryByName) != len(i.Entries) {
		return fmt.Errorf("inconsistent index state")
	}

	for _, e := range i.Entries {
		if _, ok := i.entryByName[e.Name]; !ok {
			return fmt.Errorf("inconsistent index state")
		}
	}

	sort.Slice(i.Entries, func(k, j int) bool {
		return i.Entries[k].Name < i.Entries[j].Name
	})

	return nil
}

// Write writes entries to a file.
func (i *Index) Write(path string) error {
	if err := i.Normalize(); err != nil {
		return err
	}
	indexBytes, err := yaml.Marshal(i.Entries)
	if err != nil {
		return fmt.Errorf("cannot marshal index: %w", err)
	}

	if err = os.WriteFile(path, indexBytes, writePermissions); err != nil {
		return fmt.Errorf("cannot write index to file: %w", err)
	}

	return nil
}

// Read reads entries from a file.
func (i *Index) Read(path string) error {
	bytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("cannot read index from file: %w", err)
	}

	if err := yaml.Unmarshal(bytes, &i.Entries); err != nil {
		return fmt.Errorf("cannot unmarshal index: %w", err)
	}

	i.entryByName = make(map[string]*Entry, len(i.Entries))
	for _, e := range i.Entries {
		if _, ok := i.entryByName[e.Name]; ok {
			return fmt.Errorf("duplicate entry found: %s", e.Name)
		}
		i.entryByName[e.Name] = e
	}

	return nil
}

// NewMergedIndexes initializes a MergedIndex.
func NewMergedIndexes() *MergedIndexes {
	m := &MergedIndexes{}

	m.entryByName = make(map[string]*Entry)
	m.indexByEntry = make(map[*Entry]*Index)

	return m
}

// Merge creates a new index by merging all the indexes that are passed.
// Orders matters. Be sure to pass an ordered list of indexes. For our use case, sort by added time.
func (m *MergedIndexes) Merge(indexes ...*Index) {
	for _, index := range indexes {
		for _, Entry := range index.Entries {
			m.Upsert(Entry)
			m.indexByEntry[Entry] = index
		}
	}
}

// SearchByKeywords search for entries matching the given keywords in MergedIndexes.
func (i *Index) SearchByKeywords(keywords ...string) []*Entry {
	var result []*Entry
	keywordSet := make(map[string]bool)

	for _, keyword := range keywords {
		keywordSet[keyword] = true
	}

	for _, entry := range i.Entries {
		for _, indexKeyword := range entry.Keywords {
			if _, ok := keywordSet[indexKeyword]; ok {
				result = append(result, entry)
				break
			}
		}
	}

	return result
}

// IndexByEntry is used to retrieve the original index from an entry in MergedIndexes.
func (m *MergedIndexes) IndexByEntry(entry *Entry) *Index {
	return m.indexByEntry[entry]
}
