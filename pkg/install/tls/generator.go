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

package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"time"

	logger "github.com/sirupsen/logrus"
)

// DefaultRSABits is the default bit size to generate an RSA keypair
const DefaultRSABits int = 4096

// Certs material filenames
const (
	ServerKey  = "server.key"
	ClientKey  = "client.key"
	CAKey      = "ca.key"
	CACert     = "ca.crt"
	ServerCert = "server.crt"
	ClientCert = "client.crt"
)

var certsFilenames = []string{
	ServerKey,
	ClientKey,
	CAKey,
	CACert,
	ServerCert,
	ClientCert,
}

// A GRPCTLS represents a TLS Generator for Falco
type GRPCTLS struct {
	RSABits      int
	Country      string
	Organization string
	CommonName   string
	Expiration   time.Duration
	certs        map[string]*bytes.Buffer
}

// GRPCTLSGenerator is used to init a new TLS Generator for Falco
func GRPCTLSGenerator(country, organization, name string, days int) *GRPCTLS {
	certs := make(map[string]*bytes.Buffer, len(certsFilenames))
	return &GRPCTLS{
		RSABits:      DefaultRSABits,
		Country:      country,
		Organization: organization,
		CommonName:   name,
		Expiration:   time.Duration(days) * 24 * time.Hour,
		certs:        certs,
	}
}

func (g *GRPCTLS) setKey(filename string, key *rsa.PrivateKey) error {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}); err != nil {
		return err
	}
	g.certs[filename] = buf
	return nil
}

func (g *GRPCTLS) setCert(filename string, b []byte) error {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
		return err
	}
	g.certs[filename] = buf
	return nil
}

// Generate is used to first generate TLS material in memory.
func (g *GRPCTLS) Generate() error {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	notBefore := time.Now()
	notAfter := notBefore.Add(g.Expiration)

	// CA
	caKey, err := rsa.GenerateKey(rand.Reader, g.RSABits)
	if err != nil {
		return err
	}
	g.setKey(CAKey, caKey)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{g.Organization},
			CommonName:   "Root CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	b, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	g.setCert(CACert, b)

	// Server
	serverKey, err := rsa.GenerateKey(rand.Reader, g.RSABits)
	if err != nil {
		return err
	}
	g.setKey(ServerKey, serverKey)

	serialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	serverTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{g.Organization},
			CommonName:   g.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	// todo(leogr) add support for IPAddresses
	serverTemplate.DNSNames = append(serverTemplate.DNSNames, g.CommonName)

	b, err = x509.CreateCertificate(rand.Reader, &serverTemplate, &caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return nil
	}
	g.setCert(ServerCert, b)

	// Client
	clientKey, err := rsa.GenerateKey(rand.Reader, g.RSABits)
	if err != nil {
		return err
	}
	g.setKey(ClientKey, clientKey)

	clientTemplate := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(4),
		Subject: pkix.Name{
			Organization: []string{g.Organization},
			CommonName:   g.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	b, err = x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	g.setCert(ClientCert, b)

	return nil
}

// FlushToDisk is used to persist the cert material from a GRPCTLS to disk given a path.
func (g *GRPCTLS) FlushToDisk(path string) error {
	p, err := satisfyDir(path)
	if err != nil {
		return fmt.Errorf("invalid path: %v", err)
	}
	path = p

	for _, name := range certsFilenames {
		f := filepath.Join(path, name)
		logger.Infof("Writing: %s", f)
		if err := ioutil.WriteFile(f, g.certs[name].Bytes(), 0600); err != nil {
			return fmt.Errorf(`unable to write "%s": %v`, name, err)
		}
	}
	return nil
}

func satisfyDir(dirName string) (string, error) {
	abs, err := filepath.Abs(dirName)
	if err != nil {
		return "", fmt.Errorf("unable to calculate absolute path: %v", err)
	}
	err = os.MkdirAll(abs, 0700)
	if err == nil || os.IsExist(err) {
		return abs, nil
	}
	return "", fmt.Errorf("unable to ensure dir: %v", err)
}
