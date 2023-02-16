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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// A GRPCTLS represents a TLS Generator for Falco
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

// GRPCTLSGenerator is used to init a new TLS Generator for Falco
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

// Generate is used to first generate TLS material in memory.
func (g *GRPCTLS) Generate() error {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	notBefore := time.Now()
	notAfter := notBefore.Add(g.Expiration)

	// CA certificate and key.
	caTemplate, caKey, err := g.generateCA(notBefore, notAfter, serialNumberLimit)
	if err != nil {
		return err
	}

	// Server certificate and key.
	err = g.generateServer(caTemplate, caKey, notBefore, notAfter, serialNumberLimit)
	if err != nil {
		return err
	}

	// Client certificate and key.
	err = g.generateClient(caTemplate, caKey, notBefore, notAfter)
	if err != nil {
		return err
	}

	return nil
}

func (g *GRPCTLS) generateCA(notBefore, notAfter time.Time, serialNumberLimit *big.Int) (*x509.Certificate, DSAKey, error) {
	caKey, err := g.KeyGenerator.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	g.certs[CAKey], err = g.KeyGenerator.PEMEncode(caKey)
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
	g.setCert(CACert, b)

	return caTemplate, caKey, nil
}

func (g *GRPCTLS) generateServer(caTemplate *x509.Certificate, caKey DSAKey, notBefore, notAfter time.Time, serialNumberLimit *big.Int) error {
	serverKey, err := g.KeyGenerator.GenerateKey()
	if err != nil {
		return err
	}
	g.certs[ServerKey], err = g.KeyGenerator.PEMEncode(serverKey)
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
	g.setCert(ServerCert, b)

	return nil
}

// func (g *GRPCTLS) generateClient(notBefore, notAfter time.Time) (*x509.Certificate, DSAKey, error) {
func (g *GRPCTLS) generateClient(caTemplate *x509.Certificate, caKey DSAKey, notBefore, notAfter time.Time) error {
	clientKey, err := g.KeyGenerator.GenerateKey()
	if err != nil {
		return err
	}
	g.certs[ClientKey], err = g.KeyGenerator.PEMEncode(clientKey)
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
