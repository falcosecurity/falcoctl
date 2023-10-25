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
	"context"
	"fmt"
	"io"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pterm/pterm"
	"oras.land/oras-go/v2"
)

// Tracker get an oras.Target and returns a new target that implements the tracker logic.
type Tracker func(target oras.Target) oras.Target

// NewTracker returns a new Tracker.
func NewTracker(printer *Printer, msg string) Tracker {
	if printer == nil {
		return nil
	}

	return func(target oras.Target) oras.Target {
		return NewProgressTracker(printer, target, msg)
	}
}

// ProgressTracker tracks the progress of pull and push operations.
type ProgressTracker struct {
	oras.Target
	*Printer
	msg string
}

// NewProgressTracker returns a new ProgressTracker ready to be used.
func NewProgressTracker(printer *Printer, target oras.Target, msg string) *ProgressTracker {
	return &ProgressTracker{
		Target:  target,
		Printer: printer,
		msg:     msg,
	}
}

// Push reimplements the Push function of the oras.Target interface adding the needed logic for the progress bar.
func (t *ProgressTracker) Push(ctx context.Context, expected v1.Descriptor, content io.Reader) error { //nolint:gocritic,lll // needed to implement the oras.Target interface
	d := expected.Digest.Encoded()[:12]

	t.Logger.Info(fmt.Sprintf("%s layer %s", t.msg, d))

	if !t.Printer.DisableStyling {
		t.ProgressBar, _ = NewProgressBar().
			WithTotal(int(expected.Size)).
			WithTitle(fmt.Sprintf("%s layer %s", t.msg, d)).
			Start()
	}

	reader := &trackedReader{
		Reader:      content,
		descriptor:  expected,
		progressBar: t.ProgressBar,
	}
	if err := t.Target.Push(ctx, expected, reader); err != nil {
		return err
	}

	if !t.Printer.DisableStyling {
		_, _ = t.ProgressBar.Stop()
	}

	return nil
}

// Exists if the layer already exists it prints out the correct message.
func (t *ProgressTracker) Exists(ctx context.Context, target v1.Descriptor) (bool, error) { //nolint:gocritic,lll // needed to implement the oras.Target interface
	d := target.Digest.Encoded()[:12]
	ok, err := t.Target.Exists(ctx, target)
	if err != nil {
		return ok, err
	}
	if ok {
		t.Logger.Info(fmt.Sprintf("%s: layer already exists", d))
	}
	return ok, err
}

type trackedReader struct {
	io.Reader
	descriptor  v1.Descriptor
	progressBar *pterm.ProgressbarPrinter
}

// Read implements the logic of the progress bar.
func (tr *trackedReader) Read(p []byte) (n int, err error) {
	n, err = tr.Reader.Read(p)
	if tr.progressBar != nil && tr.progressBar.IsActive {
		tr.progressBar = tr.progressBar.Add(n)
	}
	return n, err
}
