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

package tls

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/falcosecurity/falcoctl/pkg/output"
)

// A GRPCTLS represents a TLS Generator for Falco.
type GRPCTLS struct {

	// Size of the private key.
	RSABits      int
	Country      string
	Organization string
	CommonName   string
	Expiration   time.Duration
	certs        map[string]*bytes.Buffer

	// Subject Alternate Names as DNS domain names.
	DNSSANs []string

	// Subject Alternate Names as IP addresses.
	IPSANs []string

	// The digital signing algorithm to sign the key pair.
	DSA DSAType

	// KeyGenerator is the DSA-signed key generator.
	KeyGenerator DSAKeyGenerator
}

// GRPCTLSGenerator is used to init a new TLS Generator for Falco.
func GRPCTLSGenerator(
	country, organization, name string,
	days, keySize int,
	alternateNames, alternateAddresses []string, algorithm string,
	keyGenerator DSAKeyGenerator) *GRPCTLS {
	certs := make(map[string]*bytes.Buffer, len(certsFilenames))

	return &GRPCTLS{
		RSABits:      keySize,
		Country:      country,
		Organization: organization,
		CommonName:   name,
		Expiration:   time.Duration(days) * 24 * time.Hour,
		certs:        certs,
		DNSSANs:      alternateNames,
		IPSANs:       alternateAddresses,
		DSA:          DSAType(algorithm),
		KeyGenerator: keyGenerator,
	}
}

func (g *GRPCTLS) setCert(filename string, b []byte) error {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: CertificatePEMHeader, Bytes: b}); err != nil {
		return err
	}
	g.certs[filename] = buf
	return nil
}

func (g *GRPCTLS) setKey(filename string, key DSAKey) error {
	var err error
	g.certs[filename], err = g.KeyGenerator.PEMEncode(key)
	if err != nil {
		return err
	}
	return nil
}

// Generate is used to first generate TLS material in memory.
func (g *GRPCTLS) Generate() error {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	notBefore := time.Now()
	notAfter := notBefore.Add(g.Expiration)

	// CA certificate and key.
	caTemplate, caKey, err := g.GenerateCA(notBefore, notAfter, serialNumberLimit)
	if err != nil {
		return err
	}

	// Server certificate and key.
	err = g.GenerateServer(caTemplate, caKey, notBefore, notAfter, serialNumberLimit)
	if err != nil {
		return err
	}

	// Client certificate and key.
	err = g.GenerateClient(caTemplate, caKey, notBefore, notAfter)
	if err != nil {
		return err
	}

	return nil
}

// GenerateCA returns the certificate and private key pair for a certificate authority, and an error.
func (g *GRPCTLS) GenerateCA(notBefore, notAfter time.Time, serialNumberLimit *big.Int) (*x509.Certificate, DSAKey, error) {
	caKey, err := g.KeyGenerator.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	err = g.setKey(CAKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	caTemplate := &x509.Certificate{
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

	b, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		return nil, nil, err
	}
	_ = g.setCert(CACert, b)

	return caTemplate, caKey, nil
}

// GenerateServer returns the certificate and private key pair for a server, and an error.
func (g *GRPCTLS) GenerateServer(caTemplate *x509.Certificate, caKey DSAKey, notBefore, notAfter time.Time, serialNumberLimit *big.Int) error {
	serverKey, err := g.KeyGenerator.GenerateKey()
	if err != nil {
		return err
	}
	err = g.setKey(ServerKey, serverKey)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
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
		DNSNames:              g.DNSSANs,
	}
	serverTemplate.DNSNames = append(serverTemplate.DNSNames, g.CommonName)

	for _, san := range g.IPSANs {
		serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, net.ParseIP(san))
	}

	b, err := x509.CreateCertificate(rand.Reader, &serverTemplate, caTemplate, serverKey.Public(), caKey)
	if err != nil {
		return nil
	}
	_ = g.setCert(ServerCert, b)

	return nil
}

// GenerateClient returns the certificate and private key pair for a server, and an error.
func (g *GRPCTLS) GenerateClient(caTemplate *x509.Certificate, caKey DSAKey, notBefore, notAfter time.Time) error {
	clientKey, err := g.KeyGenerator.GenerateKey()
	if err != nil {
		return err
	}
	err = g.setKey(ClientKey, clientKey)
	if err != nil {
		return err
	}

	clientTemplate := &x509.Certificate{
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

	b, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, clientKey.Public(), caKey)
	if err != nil {
		return err
	}

	_ = g.setCert(ClientCert, b)

	return nil
}

// FlushToDisk is used to persist the cert material from a GRPCTLS to disk given a path.
func (g *GRPCTLS) FlushToDisk(path string, logger *output.Printer) error {
	p, err := satisfyDir(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	path = p

	for _, name := range certsFilenames {
		f := filepath.Join(path, name)
		logger.Info.Printf("Saving %s to %s\n", name, path)
		if err := os.WriteFile(f, g.certs[name].Bytes(), 0o600); err != nil {
			return fmt.Errorf("unable to write %q: %w", name, err)
		}
	}

	logger.Info.Println("Done generating the TLS certificates")
	return nil
}

// Certs returns the certificate material as map of buffers.
func (g *GRPCTLS) Certs() map[string]*bytes.Buffer {
	return g.certs
}

func satisfyDir(dirName string) (string, error) {
	abs, err := filepath.Abs(dirName)
	if err != nil {
		return "", fmt.Errorf("unable to calculate absolute path: %w", err)
	}
	err = os.MkdirAll(abs, 0o700)
	if err == nil || os.IsExist(err) {
		return abs, nil
	}

	return "", fmt.Errorf("unable to ensure dir: %w", err)
}
