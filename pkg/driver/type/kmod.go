// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package drivertype

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/falcosecurity/driverkit/cmd"
	"github.com/falcosecurity/driverkit/pkg/kernelrelease"

	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	maxRmmodWait  = 10
	rmmodWaitTime = 5 * time.Second
)

func init() {
	driverTypes[TypeKmod] = &kmod{}
}

type kmod struct{}

func (k *kmod) String() string {
	return TypeKmod
}

// Cleanup does a cleanup of existing kernel modules.
// First thing, it tries to rmmod the loaded kmod, if present.
// Then, using dkms, it tries to fetch all
// dkms-installed versions of the module to clean them up.
func (k *kmod) Cleanup(printer *output.Printer, driverName string) error {
	lsmod, err := exec.LookPath("lsmod")
	if err != nil {
		return err
	}
	rmmod, err := exec.LookPath("rmmod")
	if err != nil {
		return err
	}

	kmodName := strings.ReplaceAll(driverName, "-", "_")
	printer.Logger.Info("Check if kernel module is still loaded.")
	lsmodCmdArgs := fmt.Sprintf(`%s | cut -d' ' -f1 | grep -qx %q`, lsmod, kmodName)
	_, err = exec.Command("bash", "-c", lsmodCmdArgs).Output() //nolint:gosec // false positive
	if err == nil {
		unloaded := false
		// Module is still loaded, try to remove it
		for i := 0; i < maxRmmodWait; i++ {
			printer.Logger.Info("Kernel module is still loaded.")
			printer.Logger.Info("Trying to unload it with 'rmmod'.")
			if _, err = exec.Command(rmmod, kmodName).Output(); err == nil { //nolint:gosec // false positive
				printer.Logger.Info("OK! Unloading module succeeded.")
				unloaded = true
				break
			}
			printer.Logger.Info("Nothing to do...'falcoctl' will wait until you remove the kernel module to have a clean termination.")
			printer.Logger.Info("Check that no process is using the kernel module with 'lsmod'.")
			printer.Logger.Info("Sleep 5 seconds...")
			time.Sleep(rmmodWaitTime)
		}
		if !unloaded {
			printer.Logger.Warn("Kernel module is still loaded, you could have incompatibility issues.")
		}
	} else {
		printer.Logger.Info("OK! There is no module loaded.")
	}

	dkms, err := exec.LookPath("dkms")
	if err != nil {
		printer.Logger.Info("Skipping dkms remove (dkms not found).")
		return nil
	}

	printer.Logger.Info("Check all versions of kernel module in dkms.")
	dkmsLsCmdArgs := fmt.Sprintf(`%s status -m %q | tr -d "," | tr -d ":" | tr "/" " " | cut -d' ' -f2`, dkms, kmodName)
	out, err := exec.Command("bash", "-c", dkmsLsCmdArgs).Output() //nolint:gosec // false positive
	if err != nil {
		printer.Logger.Warn("Listing kernel module versions failed.", printer.Logger.Args("reason", err))
		return nil
	}
	if len(out) == 0 {
		printer.Logger.Info("OK! There are no module versions in dkms.")
	} else {
		printer.Logger.Info("There are some module versions in dkms.")
		outBuffer := bytes.NewBuffer(out)
		scanner := bufio.NewScanner(outBuffer)
		for scanner.Scan() {
			dVer := scanner.Text()
			dkmsRmCmdArgs := fmt.Sprintf(`%s remove -m %s -v %q --all`, dkms, kmodName, dVer)
			_, err = exec.Command("bash", "-c", dkmsRmCmdArgs).Output() //nolint:gosec // false positive
			if err == nil {
				printer.Logger.Info("OK! Removing succeeded.", printer.Logger.Args("version", dVer))
			} else {
				printer.Logger.Warn("Removing failed.", printer.Logger.Args("version", dVer))
			}
		}
	}
	return nil
}

func (k *kmod) Load(printer *output.Printer, src, driverName string, fallback bool) error {
	if fallback {
		// Try to modprobe any existent version of the kmod; this is a fallback
		// when both download and build of kmod fail.
		printer.Logger.Info("Trying to load a pre existent system module, if present.")
		_, err := exec.Command("modprobe", driverName).Output()
		if err == nil {
			printer.Logger.Info("Success: module found and loaded with modprobe.")
		} else {
			printer.Logger.Warn("Consider compiling your own driver and loading it or getting in touch with the Falco community.")
		}
		return err
	}

	chconCmdArgs := fmt.Sprintf(`chcon -t modules_object_t %q`, src)
	// We don't want to catch any error from this call
	// chcon(1): change file SELinux security context
	_, _ = exec.Command("bash", "-c", chconCmdArgs).Output() //nolint:gosec // false positive
	_, err := exec.Command("insmod", src).Output()
	if err == nil {
		printer.Logger.Info("Success: module found and loaded in dkms.", printer.Logger.Args("driver", src))
	} else {
		printer.Logger.Warn("Unable to insmod module.", printer.Logger.Args("driver", src, "err", err))
	}
	return err
}

func (k *kmod) Extension() string {
	return ".ko"
}

func (k *kmod) HasArtifacts() bool {
	return true
}

//nolint:gocritic // the method shall not be able to modify kr
func (k *kmod) Supported(kr kernelrelease.KernelRelease) bool {
	return kr.SupportsModule()
}

func (k *kmod) ToOutput(destPath string) cmd.OutputOptions {
	return cmd.OutputOptions{
		Module: destPath,
	}
}
