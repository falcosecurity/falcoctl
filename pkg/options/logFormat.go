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
	"github.com/pterm/pterm"
)

const (
	// LogFormatColor formatting option for logs.
	LogFormatColor = "color"
	// LogFormatText formatting option for logs.
	LogFormatText = "text"
	// LogFormatJSON formatting otion for logs.
	LogFormatJSON = "json"
)

var logFormats = []string{LogFormatColor, LogFormatText, LogFormatJSON}

// LogFormat data structure for log-format flag.
type LogFormat struct {
	*Enum
}

// NewLogFormat returns a new Enum configured for the log formats flag.
func NewLogFormat() *LogFormat {
	return &LogFormat{
		Enum: NewEnum(logFormats, LogFormatColor),
	}
}

// ToPtermFormatter converts the current formatter to pterm.LogFormatter.
func (lg *LogFormat) ToPtermFormatter() pterm.LogFormatter {
	var formatter pterm.LogFormatter

	switch lg.value {
	case LogFormatColor:
		formatter = pterm.LogFormatterColorful
	case LogFormatText:
		pterm.DisableColor()
		formatter = pterm.LogFormatterColorful
	case LogFormatJSON:
		formatter = pterm.LogFormatterJSON
	}
	return formatter
}
