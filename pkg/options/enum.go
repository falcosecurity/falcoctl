// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2023 The Falco Authors
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

package options

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"
)

// Enum implements the flag interface. It can be used as a base for new flags that
// can have a limited set of values.
type Enum struct {
	allowed []string
	value   string
}

// NewEnum returns an enum struct. The firs argument is a set of values allowed for the flag.
// The second argument is the default value of the flag.
func NewEnum(allowed []string, d string) *Enum {
	return &Enum{
		allowed: allowed,
		value:   d,
	}
}

// String returns the value.
func (e *Enum) String() string {
	return e.value
}

// Allowed returns the list of allowed values enclosed in parenthesis.
func (e *Enum) Allowed() string {
	return fmt.Sprintf("(%s)", strings.Join(e.allowed, ", "))
}

// Set the value for the flag.
func (e *Enum) Set(p string) error {
	if !slices.Contains(e.allowed, p) {
		return fmt.Errorf("invalid argument %q, please provide one of (%s)", p, strings.Join(e.allowed, ", "))
	}
	e.value = p
	return nil
}

// Type returns the type of the flag.
func (e *Enum) Type() string {
	return "string"
}
