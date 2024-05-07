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

package output

import (
	"github.com/pterm/pterm"

	"github.com/falcosecurity/falcoctl/pkg/enum"
)

const (
	// LogLevelInfo level option for logs.
	LogLevelInfo = "info"
	// LogLevelWarn level opiton for logs.
	LogLevelWarn = "warn"
	// LogLevelDebug level option for logs.
	LogLevelDebug = "debug"
	// LogLevelTrace level option for logs.
	LogLevelTrace = "trace"
)

var logLevels = []string{LogLevelInfo, LogLevelWarn, LogLevelDebug, LogLevelTrace}

// LogLevel data structure for log-level flag.
type LogLevel struct {
	*enum.Enum
}

// NewLogLevel returns a new Enum configured for the log level flag.
func NewLogLevel() *LogLevel {
	return &LogLevel{
		Enum: enum.NewEnum(logLevels, LogLevelInfo),
	}
}

// ToPtermLogLevel converts the current log level to pterm.LogLevel.
func (ll *LogLevel) ToPtermLogLevel() pterm.LogLevel {
	var level pterm.LogLevel
	switch ll.Value {
	case LogLevelInfo:
		level = pterm.LogLevelInfo
	case LogLevelWarn:
		level = pterm.LogLevelWarn
	case LogLevelDebug:
		level = pterm.LogLevelDebug
	case LogLevelTrace:
		level = pterm.LogLevelTrace
	}
	return level
}
