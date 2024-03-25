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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/falcosecurity/driverkit/pkg/kernelrelease"
	"golang.org/x/net/context"

	"github.com/falcosecurity/falcoctl/pkg/output"
)

const (
	// TypeKmod is the string for the bpf driver type.
	TypeKmod      = "kmod"
	maxRmmodWait  = 10
	rmmodWaitTime = 5 * time.Second
)

type errMissingDep struct {
	program string
}

func (e *errMissingDep) Error() string {
	return fmt.Sprintf("This program requires %s.", e.program)
}

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
	_, err := exec.Command("bash", "-c", "hash lsmod").Output()
	if err != nil {
		return &errMissingDep{program: "lsmod"}
	}
	_, err = exec.Command("bash", "-c", "hash rmmod").Output()
	if err != nil {
		return &errMissingDep{program: "rmmod"}
	}

	kmodName := strings.ReplaceAll(driverName, "-", "_")
	printer.Logger.Info("Check if kernel module is still loaded.")
	lsmodCmdArgs := fmt.Sprintf(`lsmod | cut -d' ' -f1 | grep -qx %q`, kmodName)
	_, err = exec.Command("bash", "-c", lsmodCmdArgs).Output() //nolint:gosec // false positive
	if err == nil {
		unloaded := false
		// Module is still loaded, try to remove it
		for i := 0; i < maxRmmodWait; i++ {
			printer.Logger.Info("Kernel module is still loaded.")
			printer.Logger.Info("Trying to unload it with 'rmmod'.")
			if _, err = exec.Command("rmmod", kmodName).Output(); err == nil { //nolint:gosec // false positive
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

	_, err = exec.Command("bash", "-c", "hash dkms").Output()
	if err != nil {
		printer.Logger.Info("Skipping dkms remove (dkms not found).")
		return nil
	}

	printer.Logger.Info("Check all versions of kernel module in dkms.")
	dkmsLsCmdArgs := fmt.Sprintf(`dkms status -m %q | tr -d "," | tr -d ":" | tr "/" " " | cut -d' ' -f2`, kmodName)
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
			dkmsRmCmdArgs := fmt.Sprintf(`dkms remove -m %s -v %q --all`, kmodName, dVer)
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

func createDKMSMakeFile(gcc string) error {
	file, err := os.OpenFile("/tmp/falco-dkms-make", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o777) //nolint:gosec // we need the file to be executable
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = fmt.Fprintln(file, "#!/usr/bin/env bash")
	if err == nil {
		_, err = fmt.Fprintln(file, `make CC=`+gcc+` $@`)
	}
	return err
}

//nolint:gocritic // the method shall not be able to modify kr
func (k *kmod) Build(ctx context.Context,
	printer *output.Printer,
	kr kernelrelease.KernelRelease,
	driverName, driverVersion string,
	_ map[string]string,
) (string, error) {
	// Skip dkms on UEK hosts because it will always fail
	if strings.Contains(kr.String(), "uek") {
		printer.Logger.Warn("Skipping because the dkms install always fail (on UEK hosts).")
		return "", fmt.Errorf("unsupported on uek hosts")
	}

	out, err := exec.Command("which", "gcc").Output()
	if err != nil {
		return "", err
	}
	gccDir := filepath.Dir(string(out))

	gccs, err := filepath.Glob(gccDir + "/gcc*")
	if err != nil {
		return "", err
	}

	for _, gcc := range gccs {
		// Filter away gcc-{ar,nm,...}
		// Only gcc compiler has `-print-search-dirs` option.
		gccSearchArgs := fmt.Sprintf(`%s -print-search-dirs 2>&1 | grep "install:"`, gcc)
		_, err = exec.Command("bash", "-c", gccSearchArgs).Output() //nolint:gosec // false positive
		if err != nil {
			continue
		}

		printer.Logger.Info("Trying to dkms install module.", printer.Logger.Args("gcc", gcc))
		err = createDKMSMakeFile(gcc)
		if err != nil {
			printer.Logger.Warn("Could not fill /tmp/falco-dkms-make content.")
			continue
		}
		dkmsCmdArgs := fmt.Sprintf(`dkms install --directive="MAKE='/tmp/falco-dkms-make'" -m %q -v %q -k %q --verbose`,
			driverName, driverVersion, kr.String())

		// Try the build through dkms
		out, err = exec.CommandContext(ctx, "bash", "-c", dkmsCmdArgs).CombinedOutput() //nolint:gosec // false positive
		if err == nil {
			koGlob := fmt.Sprintf("/var/lib/dkms/%s/%s/%s/%s/module/%s", driverName, driverVersion, kr.String(), kr.Architecture.ToNonDeb(), driverName)
			var koFiles []string
			koFiles, err = filepath.Glob(koGlob + ".*")
			if err != nil || len(koFiles) == 0 {
				printer.Logger.Warn("Module file not found.")
				continue
			}
			koFile := koFiles[0]
			printer.Logger.Info("Module installed in dkms.", printer.Logger.Args("file", koFile))
			return koFile, nil
		}
		printer.DefaultText.Print(string(out))
		dkmsLogFile := fmt.Sprintf("/var/lib/dkms/%s/%s/build/make.log", driverName, driverVersion)
		logs, err := os.ReadFile(filepath.Clean(dkmsLogFile))
		if err != nil {
			printer.Logger.Warn("Running dkms build failed, couldn't find dkms log", printer.Logger.Args("file", dkmsLogFile))
		} else {
			printer.Logger.Warn("Running dkms build failed. Dumping dkms log.", printer.Logger.Args("file", dkmsLogFile))
			logBuf := bytes.NewBuffer(logs)
			scanner := bufio.NewScanner(logBuf)
			for scanner.Scan() {
				m := scanner.Text()
				printer.DefaultText.Println(m)
			}
		}
	}
	return "", fmt.Errorf("failed to compile the module")
}
