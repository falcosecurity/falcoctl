package registry

import (
	"io"
	"strings"

	"gopkg.in/yaml.v2"
)

type SourcingCapability struct {
	Supported bool   `yaml:"supported"`
	ID        uint   `yaml:"id"`
	Source    string `yaml:"source"`
}

type ExtractionCapability struct {
	Supported bool     `yaml:"supported"`
	Sources   []string `yaml:"sources"`
}

type Capabilities struct {
	Sourcing   SourcingCapability   `yaml:"sourcing"`
	Extraction ExtractionCapability `yaml:"extraction"`
}

type Plugin struct {
	Name         string       `yaml:"name"`
	Description  string       `yaml:"description"`
	Authors      string       `yaml:"authors"`
	Contact      string       `yaml:"contact"`
	URL          string       `yaml:"url"`
	License      string       `yaml:"license"`
	Reserved     bool         `yaml:"reserved"`
	Capabilities Capabilities `yaml:"capabilities"`
}

type Registry struct {
	Plugins         []Plugin `yaml:"plugins"`
	ReservedSources []string `yaml:"reserved_sources"`
}

func (r *Registry) SearchByKeywords(keywords []string) []Plugin {
	plugins := make([]Plugin, 0)
	for _, plugin := range r.Plugins {
		for _, keyword := range keywords {
			if strings.Contains(strings.ToLower(plugin.Name), strings.ToLower(keyword)) ||
				strings.Contains(strings.ToLower(plugin.Description), strings.ToLower(keyword)) {
				plugins = append(plugins, plugin)
			}
		}
	}
	return plugins
}

func (p *Plugin) ToString() (string, error) {
	bytes, err := yaml.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func LoadRegistry(r *io.ReadCloser) (*Registry, error) {
	decoder := yaml.NewDecoder(*r)
	registry := &Registry{}
	if err := decoder.Decode(registry); err != nil {
		return nil, err
	}
	return registry, nil
}
