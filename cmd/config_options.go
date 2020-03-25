/*
Copyright © 2019 The Falco Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"

	"github.com/creasty/defaults"
	"github.com/falcosecurity/falcoctl/validate"
	"github.com/go-playground/validator/v10"
	logger "github.com/kris-nova/logger"
)

// ConfigOptions represent the persistent configuration flags of falcoctl.
type ConfigOptions struct {
	ConfigFile string `name:"config"`
	Verbose    int    `validate:"number,min=0,max=4" default:"3" name:"verbose"`
	Fabulous   bool   `name:"fab"`
}

// NewConfigOptions creates an instance of ConfigOptions.
func NewConfigOptions() *ConfigOptions {
	o := &ConfigOptions{}
	if err := defaults.Set(o); err != nil {
		logger.Critical("error setting falcoctl options default")
	}
	return o
}

// Validate validates the ConfigOptions fields.
func (co *ConfigOptions) Validate() []error {
	if err := validate.V.Struct(co); err != nil {
		errors := err.(validator.ValidationErrors)
		errArr := []error{}
		for _, e := range errors {
			// Translate each error one at a time
			errArr = append(errArr, fmt.Errorf(e.Translate(validate.T)))
		}
		return errArr
	}
	return nil
}
