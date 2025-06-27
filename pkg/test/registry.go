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

package test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/configuration"
	"github.com/distribution/distribution/v3/registry"
	oaerrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/generates"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/golang-jwt/jwt/v5"
)

// RegistryTLSConfig maintains all certificate informations.
type RegistryTLSConfig struct {
	CipherSuites    []string
	CertificatePath string
	PrivateKeyPath  string
	Certificate     *tls.Certificate
}

// FreePort get a free port on the system by listening in a socket,
// checking the bound port number and then closing the socket.
func FreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// BuildRegistryTLSConfig creates a new RegistryTLSConfig.
func BuildRegistryTLSConfig(tmpDir string, cipherSuites []string) (*RegistryTLSConfig, error) {
	var priv interface{}
	var pub crypto.PublicKey
	var err error

	name := "cert"

	priv, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to create rsa private key: %w", err)
	}
	rsaKey := priv.(*rsa.PrivateKey)
	pub = rsaKey.Public()

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Minute)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to create serial number: %w", err)
	}
	cert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"registry_test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &cert, &cert, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPath := path.Join(tmpDir, name+".pem")
	certOut, err := os.Create(filepath.Clean(certPath))
	if err != nil {
		return nil, fmt.Errorf("failed to create pem: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return nil, fmt.Errorf("failed to write data to %s: %w", certPath, err)
	}
	if err := certOut.Close(); err != nil {
		return nil, fmt.Errorf("error closing %s: %w", certPath, err)
	}

	pkPath := path.Join(tmpDir, "key.pem")
	keyOut, err := os.OpenFile(filepath.Clean(pkPath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s for writing: %w", tmpDir, err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal private key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return nil, fmt.Errorf("failed to write data to key.pem: %w", err)
	}
	if err := keyOut.Close(); err != nil {
		return nil, fmt.Errorf("error closing %s: %w", pkPath, err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	tlsTestCfg := RegistryTLSConfig{
		CipherSuites:    cipherSuites,
		CertificatePath: certPath,
		PrivateKeyPath:  pkPath,
		Certificate:     &tlsCert,
	}

	return &tlsTestCfg, nil
}

// StartRegistry starts a new OCI registry and returns it's address.
func StartRegistry(ctx context.Context, cfg *configuration.Configuration) error {
	if cfg.Storage == nil {
		cfg.Storage = map[string]configuration.Parameters{"inmemory": map[string]interface{}{}}
	}

	// Create registry.
	reg, err := registry.NewRegistry(ctx, cfg)
	if err != nil {
		return err
	}

	// Start serving in goroutine and listen for stop signal in main thread
	return reg.ListenAndServe()
}

// StartOAuthServer starts a new OAuth server.
func StartOAuthServer(ctx context.Context, port int) error {
	manager := manage.NewDefaultManager()
	// token memory store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// client memory store
	clientStore := store.NewClientStore()
	err := clientStore.Set("000000", &models.Client{
		ID:     "000000",
		Secret: "999999",
		Domain: "http://localhost:3000/callback",
		UserID: "user",
	})
	if err != nil {
		return err
	}
	manager.MapClientStorage(clientStore)

	manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("secret"), jwt.SigningMethodHS256))

	// config used for client credentials
	cfg := &manage.Config{
		AccessTokenExp:    60 * time.Second,
		RefreshTokenExp:   0,
		IsGenerateRefresh: false,
	}
	manager.SetClientTokenCfg(cfg)

	// useful to test other grant types
	refreshTokenConfig := &manage.RefreshingConfig{
		AccessTokenExp:     time.Second * 3,
		RefreshTokenExp:    time.Hour * 24,
		IsGenerateRefresh:  true,
		IsResetRefreshTime: false,
		IsRemoveAccess:     false,
		IsRemoveRefreshing: false,
	}
	manager.SetRefreshTokenCfg(refreshTokenConfig)

	srv := server.NewDefaultServer(manager)

	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetInternalErrorHandler(func(err error) (re *oaerrors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *oaerrors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (string, error) {
		return "id", nil
	})

	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		if clientID == "000000" && username == "username" && password == "password" {
			return username, nil
		}
		return "", oaerrors.ErrAccessDenied
	})

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	http.HandleFunc("/hitme", func(w http.ResponseWriter, r *http.Request) {
		_, err = w.Write([]byte("ok hit"))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	})

	// Token introspection endpoint
	http.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		accessToken := r.FormValue("token")
		accessToken = strings.TrimPrefix(accessToken, "Bearer ")
		ti, err := srv.Manager.LoadAccessToken(ctx, accessToken)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		if duration := ti.GetAccessExpiresIn(); duration <= 0 {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
	})

	s := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		ReadHeaderTimeout: 3 * time.Second,
	}

	log.Fatal(s.ListenAndServe())
	return nil
}
