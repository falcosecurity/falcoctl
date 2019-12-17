/*
Copyright © 2019 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tls

import (
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"

	"github.com/kris-nova/logger"

	"github.com/spacemonkeygo/openssl"
)

const (
	DefaultRSABytes   int = 4096
	DefaultServerKey      = "server.key"
	DefaultCAKey          = "ca.key"
	DefaultServerCSR      = "server.csr"
	DefaultCACert         = "ca.crt"
	DefaultServerCert     = "server.crt"
)

var (
	DefaultX509SubjectFields = map[string]string{
		"C":  "SP",
		"ST": "US",
		"L":  "San Francisco",
		"O":  "Default",
		"OU": "Default",
		"CN": "Root CA",
	}
)

type GRPCTLSGenerator struct {
	RSABytes      int
	Country       string
	Organization  string
	CommonName    string
	SubjectFields map[string]string
	CACert        *openssl.Certificate
	ServerCert    *openssl.Certificate
	ServerCSR     *openssl.Certificate
	CAKey         openssl.PrivateKey
	ServerKey     openssl.PrivateKey
}

// NewGRPCTLSGenerator is used to init a new TLS Generator for Falco
func NewGRPCTLSGenerator(country, organization, name string) *GRPCTLSGenerator {
	return &GRPCTLSGenerator{
		RSABytes:      DefaultRSABytes,
		Country:       country,
		Organization:  organization,
		CommonName:    name,
		SubjectFields: DefaultX509SubjectFields,
	}
}

// Generate is used to first generate TLS material in memory.
func (g *GRPCTLSGenerator) Generate() error {
	i64 := &big.Int{}
	i64.SetInt64(01)
	caKey, err := openssl.GenerateRSAKey(g.RSABytes)
	if err != nil {
		return fmt.Errorf("unable to generate RSA key: %v", err)
	}

	certificateSigningInfo := &openssl.CertificateInfo{
		Serial:       i64,
		Issued:       0,
		Expires:      0,
		Country:      g.Country,
		Organization: g.Organization,
		CommonName:   g.CommonName,
	}
	caCert, err := openssl.NewCertificate(certificateSigningInfo, caKey)
	if err != nil {
		return fmt.Errorf("unable to generate new signing certificate: %v", err)
	}
	name := &openssl.Name{}
	name.AddTextEntries(g.SubjectFields)
	caCert.SetSubjectName(name)
	caCert.SetVersion(openssl.X509_V3)
	err = caCert.Sign(caKey, openssl.EVP_SHA256)
	if err != nil {
		return fmt.Errorf("unable to sign caCert: %v", err)
	}

	//$ openssl genrsa -passout pass:1234 -des3 -out server.key 4096
	serverKey, err := openssl.GenerateRSAKey(g.RSABytes)
	if err != nil {
		return fmt.Errorf("unable to generate server RSA key: %v", err)
	}

	//$ openssl req -passin pass:1234 -new -key server.key -out server.csr -subj  "/C=SP/ST=Italy/L=Ornavasso/O=Test/OU=Server/CN=localhost"
	serverCertificateSigningInfo := &openssl.CertificateInfo{
		Serial:       i64,
		Issued:       0,
		Expires:      0,
		Country:      g.Country,
		Organization: g.Organization,
		CommonName:   g.CommonName,
	}
	serverCSR, err := openssl.NewCertificate(serverCertificateSigningInfo, serverKey)
	if err != nil {
		return fmt.Errorf("unable to generate new signing certificate: %v", err)
	}
	serverName := &openssl.Name{}
	serverName.AddTextEntries(g.SubjectFields)
	serverCSR.SetSubjectName(name)
	serverCSR.SetVersion(openssl.X509_V3)
	err = serverCSR.Sign(serverKey, openssl.EVP_SHA256)
	if err != nil {
		return fmt.Errorf("unable to sign serverCSR: %v", err)
	}
	serverCASigningInfo := &openssl.CertificateInfo{
		Serial:       i64,
		Issued:       0,
		Expires:      0,
		Country:      g.Country,
		Organization: g.Organization,
		CommonName:   g.CommonName,
	}
	serverCert, err := openssl.NewCertificate(serverCASigningInfo, serverKey)
	if err != nil {
		return fmt.Errorf("unable to create new server cert: %v", err)
	}
	serverCert.SetIssuer(caCert)

	err = serverCert.Sign(serverKey, openssl.EVP_SHA256)
	if err != nil {
		return fmt.Errorf("unable to sign serverCert: %v", err)
	}
	err = serverCert.Sign(caKey, openssl.EVP_SHA256)
	if err != nil {
		return fmt.Errorf("unable to sign serverCert: %v", err)
	}

	// Cache TLS Cert material
	g.CACert = caCert
	g.ServerCert = serverCert
	g.ServerCSR = serverCSR
	g.CAKey = caKey
	g.ServerKey = serverKey

	return nil
}

// FlushToDisk is used to persist the cert material from a GRPCTLSGenerator to disk given a path.
func (g *GRPCTLSGenerator) FlushToDisk(path string) error {
	p, err := satisfyDir(path)
	if err != nil {
		return fmt.Errorf("invalid path: %v", err)
	}
	path = p

	// --- Write server.crt
	serverCert, err := g.ServerCert.MarshalPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for serverCRT: %v", err)
	}
	f := filepath.Join(path, DefaultServerCert)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, serverCert, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}

	// --- Write ca.crt
	caCert, err := g.CACert.MarshalPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for caCert: %v", err)
	}
	f = filepath.Join(path, DefaultCACert)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, caCert, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}
	// --- Write server.csr
	serverCSR, err := g.ServerCSR.MarshalPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for serverCSR: %v", err)
	}
	f = filepath.Join(path, DefaultServerCSR)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, serverCSR, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}

	// --- Write ca.key
	caKey, err := g.CAKey.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for caKey: %v", err)
	}
	f = filepath.Join(path, DefaultCAKey)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, caKey, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}

	// --- Write server.key
	serverKey, err := g.ServerKey.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("unable to marshal PEM data for serverKey: %v", err)
	}
	f = filepath.Join(path, DefaultServerKey)
	logger.Always("Writing: %s", f)
	err = ioutil.WriteFile(f, serverKey, 0600)
	if err != nil {
		return fmt.Errorf("error writing [%s]: %v", f, err)
	}
	return nil
}

func satisfyDir(dirName string) (string, error) {
	abs, err := filepath.Abs(dirName)
	if err != nil {
		return "", fmt.Errorf("unable to calculate absolute path: %v", err)
	}
	err = os.MkdirAll(abs, 0644)
	if err == nil || os.IsExist(err) {
		return abs, nil
	}
	return "", fmt.Errorf("unable to ensure dir: %v", err)
}
