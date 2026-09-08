// Package identity persists device keys and authenticates peers by certificate pin.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type Identity struct {
	Certificate tls.Certificate
	ID          string
}

func LoadOrCreate(stateDir string) (*Identity, error) {
	certPath, keyPath := filepath.Join(stateDir, "cert.pem"), filepath.Join(stateDir, "key.pem")
	_, certErr := os.Lstat(certPath)
	_, keyErr := os.Lstat(keyPath)
	if !os.IsNotExist(certErr) || !os.IsNotExist(keyErr) {
		return Load(stateDir)
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Backuply device"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	// Publish complete files without overwriting an existing identity. An interrupted
	// pair remains an explicit recovery error, never an automatic key rotation.
	if err := writeExclusive(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return nil, err
	}
	if err := writeExclusive(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return nil, err
	}
	return Load(stateDir)
}

func writeExclusive(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Link(f.Name(), path); err != nil {
		return fmt.Errorf("publish identity: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func Load(stateDir string) (*Identity, error) {
	certPath, keyPath := filepath.Join(stateDir, "cert.pem"), filepath.Join(stateDir, "key.pem")
	for _, path := range []string{certPath, keyPath} {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("identity is missing or incomplete: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("identity file %s must be a regular file", path)
		}
		if path == keyPath && info.Mode().Perm()&0077 != 0 {
			return nil, fmt.Errorf("private key permissions must be 0600 or stricter")
		}
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load device identity: %w", err)
	}
	if len(pair.Certificate) != 1 {
		return nil, fmt.Errorf("identity must contain one self-signed certificate")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if err := validateCertificate(leaf); err != nil {
		return nil, err
	}
	if _, ok := pair.PrivateKey.(ed25519.PrivateKey); !ok {
		return nil, fmt.Errorf("identity private key must be Ed25519")
	}
	pair.Leaf = leaf
	return &Identity{Certificate: pair, ID: fingerprint(leaf.Raw)}, nil
}

func fingerprint(der []byte) string { sum := sha256.Sum256(der); return hex.EncodeToString(sum[:]) }

func validateCertificate(cert *x509.Certificate) error {
	if cert.PublicKeyAlgorithm != x509.Ed25519 {
		return fmt.Errorf("device certificate must use Ed25519")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("device certificate is outside its validity period")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("device certificate must allow digital signatures")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return fmt.Errorf("device certificate is not self-signed: %w", err)
	}
	return nil
}

func verifyPeer(state tls.ConnectionState, allowed map[string]bool) error {
	if len(state.PeerCertificates) != 1 {
		return fmt.Errorf("peer must supply exactly one device certificate")
	}
	cert := state.PeerCertificates[0]
	if err := validateCertificate(cert); err != nil {
		return err
	}
	if !allowed[fingerprint(cert.Raw)] {
		return fmt.Errorf("untrusted device certificate fingerprint")
	}
	return nil
}

func (i *Identity) ServerTLS(allowedIDs []string) *tls.Config {
	allowed := make(map[string]bool, len(allowedIDs))
	for _, id := range allowedIDs {
		allowed[id] = true
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{i.Certificate},
		ClientAuth:       tls.RequireAnyClientCert,
		VerifyConnection: func(s tls.ConnectionState) error { return verifyPeer(s, allowed) },
	}
}

func (i *Identity) ClientTLS(expectedID string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{i.Certificate},
		// Explicit certificate pin verification replaces the public PKI and DNS
		// checks. VerifyConnection also runs on resumed connections.
		InsecureSkipVerify: true,
		VerifyConnection:   func(s tls.ConnectionState) error { return verifyPeer(s, map[string]bool{expectedID: true}) },
	}
}
