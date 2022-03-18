package registry

import (
	"io"
	"strings"

	"gopkg.in/yaml.v2"
)

type Source struct {
	ID          uint   `yaml:"id"`
	Source      string `yaml:"source"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Authors     string `yaml:"authors"`
	Contact     string `yaml:"contact"`
	URL         string `yaml:"url"`
	License     string `yaml:"license"`
	Reserved    bool   `yaml:"reserved"`
}

type Extractor struct {
	Sources     []string `yaml:"sources"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Authors     string   `yaml:"authors"`
	Contact     string   `yaml:"contact"`
	URL         string   `yaml:"url"`
	License     string   `yaml:"license"`
	Reserved    bool     `yaml:"reserved"`
}

type Plugins struct {
	Source    []Source    `yaml:"source"`
	Extractor []Extractor `yaml:"extractor"`
}

func (p *Plugins) ToString() (string, error) {
	bytes, err := yaml.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

type Registry struct {
	Plugins         Plugins  `yaml:"plugins"`
	ReservedSources []string `yaml:"reserved_sources"`
}

func (r *Registry) SearchByKeywords(keywords []string) *Plugins {
	plugins := &Plugins{}
	for _, source := range r.Plugins.Source {
		for _, keyword := range keywords {
			if strings.Contains(strings.ToLower(source.Description), strings.ToLower(keyword)) {
				plugins.Source = append(plugins.Source, source)
			} else if strings.Contains(strings.ToLower(source.Name), strings.ToLower(keyword)) {
				plugins.Source = append(plugins.Source, source)
			}
		}
	}
	for _, extractor := range r.Plugins.Extractor {
		for _, keyword := range keywords {
			if strings.Contains(strings.ToLower(extractor.Description), strings.ToLower(keyword)) {
				plugins.Extractor = append(plugins.Extractor, extractor)
			} else if strings.Contains(strings.ToLower(extractor.Name), strings.ToLower(keyword)) {
				plugins.Extractor = append(plugins.Extractor, extractor)
			}
		}
	}
	return plugins
}

func LoadRegistry(r *io.ReadCloser) (*Registry, error) {
	decoder := yaml.NewDecoder(*r)
	registry := &Registry{}
	if err := decoder.Decode(registry); err != nil {
		return nil, err
	}
	return registry, nil
}
