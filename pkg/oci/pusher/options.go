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

package pusher

type opts struct {
	Platform     string
	Dependencies []string
}

// Option is a functional option for pusher.
type Option func(*opts) error

// Options is a slice of Option.
type Options []Option

// apply interates over Options and calls each functional option with a given pusher.
func (o Options) apply(oo *opts) error {
	for _, f := range o {
		if err := f(oo); err != nil {
			return err
		}
	}
	return nil
}

// WithPlatform sets the platform option.
func WithPlatform(platform string) Option {
	return func(o *opts) error {
		o.Platform = platform
		return nil
	}
}

// WithDependencies sets the dependencies option.
//
// Dependencies can be expressed in the format "artifact-name:1.0.0"
// (use "|" to append alternatives, eg. "|alternative-a:1.0.0|alternative-b:1.0.0").
func WithDependencies(deps ...string) Option {
	return func(o *opts) error {
		o.Dependencies = deps
		return nil
	}
}
