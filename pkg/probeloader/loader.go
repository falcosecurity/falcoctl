package probeloader

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"unsafe"

	"github.com/kris-nova/logger"
	"golang.org/x/sys/unix"
)

// GetKernelRelease gets the current kernel release
func GetKernelRelease() (release string, err error) {
	name := &unix.Utsname{}
	err = unix.Uname(name)
	if err != nil {
		return release, err
	}
	release = string(name.Release[:bytes.IndexByte(name.Release[:], 0)])
	return release, err
}

// GetKernelConfigHash gets the hash of the current kernel's configuration
func GetKernelConfigHash() (string, error) {
	var hash string
	kernelConfigPath, err := getKernelConfigPath()
	if err != nil {
		return hash, err
	}
	hash, err = genKernelConfigHash(kernelConfigPath)
	if err != nil {
		return hash, err
	}
	return hash, err
}

func getKernelConfigPath() (string, error) {
	var err error
	kernelConfigPath := ""

	version, _ := GetKernelRelease()
	paths := []string{
		"/proc/config.gz",
		"/boot/config-" + version,
		"/host/boot/config-" + version,
		"/usr/lib/ostree-boot/config-" + version,
		"/usr/lib/ostree-boot/config-" + version,
		"/lib/modules/" + version + "/config"}

	for _, path := range paths {
		_, err := os.Stat(path)
		if err != nil {
			continue
		}
		return path, err
	}
	return kernelConfigPath, err
}

func genKernelConfigHash(path string) (string, error) {
	var md5hash string
	var err error

	file, err := os.Open(path)
	if err != nil {
		return md5hash, err
	}
	defer file.Close()

	fileBuf := bytes.NewBuffer(nil)
	io.Copy(fileBuf, file)

	filetype := http.DetectContentType(fileBuf.Bytes())

	if filetype == "application/x-gzip" {
		gzipFile, err := gzip.NewReader(fileBuf)
		if err != nil {
			return md5hash, err
		}
		defer gzipFile.Close()
		fileBuf = bytes.NewBuffer(nil)
		io.Copy(fileBuf, gzipFile)
	}

	hash := md5.New()
	if _, err := io.Copy(hash, fileBuf); err != nil {
		return md5hash, err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// FetchModule looks for the Falco module and downloads it if found
func FetchModule(url string, path string) error {
	logger.Always("Downloading kernel module from %s", url)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	logger.Always("Recevied HTTP Status Code: %d", resp.StatusCode)
	if resp.StatusCode == http.StatusOK {
		out, err := os.Create(path)
		if err != nil {
			logger.Critical("Error creating file: %s", path)
			return err
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			logger.Critical("Unable to write file: %s", path)
			return err
		}
		logger.Always("Wrote kernel module: %s", path)
	} else {
		logger.Critical("Non-200 Status code received %d", resp.StatusCode)
	}
	return err
}

// LoadModule loads the falco kernel module into the current kernel
func LoadModule(path string) error {
	file, err := os.Open(path)
	if err != nil {
		logger.Critical("Error opening kernel module: %s", path)
		return err
	}

	logger.Always("Opened probe: %s", path)

	p0, err := unix.BytePtrFromString("")

	if _, _, err := unix.Syscall(313, file.Fd(), uintptr(unsafe.Pointer(p0)), 0); err != 0 {
		logger.Critical("Error loading kernel module: %s. The module may already be loaded.", path)
		return err
	}

	return err
}
