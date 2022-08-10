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

package repo

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"
)

const (
	timeformat = "2006-01-02 15:04:05"
	writeperm  = 0666
)

type RepoList struct {
	Sources []RepoEntry `yaml:"sources"`
}

type RepoEntry struct {
	Name string `yaml:"name"`
	Url  string `yaml:"url"`
	Date string `yaml:"updated"`
}

func LoadRepos(path string) (*RepoList, error) {
	list := &RepoList{}
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(file, list)
	if err != nil {
		return nil, err
	}
	return list, nil
}

func WriteRepos(path string, repos *RepoList) error {
	data, err := yaml.Marshal(repos)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path, data, writeperm)
	if err != nil {
		return err
	}
	return nil
}

func (r *RepoList) AddRepo(name string, url string) error {
	tm := time.Now().Format(timeformat)
	//Error if entry "name" already present
	for _, k := range r.Sources {
		if k.Name == name {
			return fmt.Errorf("Artifact repository %s (%s) already present.", k.Name, k.Url)
		}
	}
	//Append otherwise
	r.Sources = append(r.Sources, RepoEntry{Name: name, Url: url, Date: tm})
	return nil
}

// RemoveRepo removes an entry from sources.yaml, and the corresponding repository index file, if present
func (r *RepoList) RemoveRepo(name string, idxpath string) error {
	for i, k := range r.Sources {
		if k.Name == name {
			copy(r.Sources[i:], r.Sources[i+1:])
			r.Sources = r.Sources[:len(r.Sources)-1]
			// Home/.falcoctl/myindex.yaml
			fname := filepath.Join(idxpath, name+".yaml")
			_, err := os.Stat(fname)
			if os.IsNotExist(err) {
				return nil
			}
			err = os.Remove(fname)
			return err
		}
	}
	return nil
}

func RemoveAll(repof string, idxpath string) error {
	r, err := LoadRepos(repof)
	if err != nil {
		return err
	}
	//Removes each repo index file
	for _, k := range r.Sources {
		_, err := os.Stat(k.Name)
		if os.IsNotExist(err) {
			break
		}
		if err != nil {
			return err
		}
		err = os.Remove(filepath.Join(idxpath, k.Name+".yaml"))
		if err != nil {
			return err
		}
	}
	//Write empty source.yaml
	err = os.Truncate(repof, 0)
	if err != nil {
		return err
	}
	return nil
}
