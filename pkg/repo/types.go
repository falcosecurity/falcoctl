package repo

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"time"
)

const (
	timeformat = "2006-01-02 15:04:05"
	writeperm  = 0777
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
