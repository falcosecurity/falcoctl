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

package output

import (
	"context"
	"fmt"
	"io"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pterm/pterm"
	"oras.land/oras-go/v2"
)

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
	progressBar, _ := t.ProgressBar.WithTotal(int(expected.Size)).WithTitle(fmt.Sprintf(" INFO  %s %s:", t.msg, d)).WithShowCount(false).Start()

	reader := &trackedReader{
		Reader:      content,
		descriptor:  expected,
		progressBar: progressBar,
	}
	err := t.Target.Push(ctx, expected, reader)
	_, _ = progressBar.Stop()
	if err != nil {
		t.Error.Printfln("unable to push artifact %s", err)
		return err
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
		t.Info.Printfln("%s: layer already exists", d)
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
	if tr.progressBar.IsActive {
		tr.progressBar = tr.progressBar.Add(n)
	}
	return n, err
}
