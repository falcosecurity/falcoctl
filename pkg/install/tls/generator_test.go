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

package tls_test

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/falcoctl/pkg/install/tls"
)

func TestGenerateCA(t *testing.T) {
	gen := buildGRPCTLSGenerator()
	notBefore, notAfter, serialNumberLimit := getCertsParams(gen)

	_, _, err := gen.GenerateCA(notBefore, notAfter, serialNumberLimit)

	assert.Nil(t, err)
	assert.NotNil(t, gen.Certs()[tls.CACert])
	assert.NotNil(t, gen.Certs()[tls.CAKey])

	block, _ := pem.Decode(gen.Certs()[tls.CAKey].Bytes())
	_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	assert.Nil(t, err)
}

func TestGenerateServer(t *testing.T) {
	gen := buildGRPCTLSGenerator()
	notBefore, notAfter, serialNumberLimit := getCertsParams(gen)

	caCrt, caKey, _ := gen.GenerateCA(notBefore, notAfter, serialNumberLimit)
	err := gen.GenerateServer(caCrt, caKey, notBefore, notAfter, serialNumberLimit)

	assert.Nil(t, err)
	assert.NotNil(t, gen.Certs()[tls.ServerCert])
	assert.NotNil(t, gen.Certs()[tls.ServerKey])

	block, _ := pem.Decode(gen.Certs()[tls.ServerKey].Bytes())
	_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	assert.Nil(t, err)
}

func TestGenerateClient(t *testing.T) {
	gen := buildGRPCTLSGenerator()
	notBefore, notAfter, serialNumberLimit := getCertsParams(gen)

	caCrt, caKey, _ := gen.GenerateCA(notBefore, notAfter, serialNumberLimit)
	err := gen.GenerateClient(caCrt, caKey, notBefore, notAfter)

	assert.Nil(t, err)
	assert.NotNil(t, gen.Certs()[tls.ClientCert])
	assert.NotNil(t, gen.Certs()[tls.ClientKey])

	block, _ := pem.Decode(gen.Certs()[tls.ClientKey].Bytes())
	_, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	assert.Nil(t, err)
}

func buildGRPCTLSGenerator() *tls.GRPCTLS {
	keyGen := tls.NewKeyGenerator(tls.RSAType)
	return tls.GRPCTLSGenerator("", "", "", 30, 2048, []string{}, []string{}, "rsa", keyGen)
}

func getCertsParams(gen *tls.GRPCTLS) (notBefore, notAfter time.Time, serialNumberLimit *big.Int) {
	serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)
	notBefore = time.Now()
	notAfter = notBefore.Add(gen.Expiration)

	return
}
