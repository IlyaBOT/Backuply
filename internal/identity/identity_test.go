package identity

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newIdentity(t *testing.T) *Identity {
	t.Helper()
	i, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func TestIdentityPersistence(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || len(first.ID) != 64 {
		t.Fatalf("identity changed: %s / %s", first.ID, second.ID)
	}
	info, err := os.Stat(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key permissions %o", info.Mode().Perm())
	}
}

func TestRejectPartialCorruptAndExposedIdentity(t *testing.T) {
	for _, file := range []string{"key.pem", "cert.pem"} {
		t.Run(file, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, file), []byte("broken"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOrCreate(dir); err == nil {
				t.Fatal("replaced partial identity")
			}
			data, err := os.ReadFile(filepath.Join(dir, file))
			if err != nil || string(data) != "broken" {
				t.Fatal("changed corrupt identity")
			}
		})
	}
	dir := t.TempDir()
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "key.pem"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("accepted world-readable private key")
	}
}

func handshake(t *testing.T, serverConfig, clientConfig *tls.Config) (error, error) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		err = conn.(*tls.Conn).Handshake()
		if err == nil {
			_, err = conn.Write([]byte("ok"))
		}
		serverDone <- err
	}()
	conn, clientErr := tls.Dial("tcp", listener.Addr().String(), clientConfig)
	if clientErr == nil {
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 2)
		_, clientErr = conn.Read(buf)
		conn.Close()
	}
	return <-serverDone, clientErr
}

func TestMutualTLSPins(t *testing.T) {
	server, client := newIdentity(t), newIdentity(t)
	serverErr, clientErr := handshake(t, server.ServerTLS([]string{client.ID}), client.ClientTLS(server.ID))
	if serverErr != nil || clientErr != nil {
		t.Fatalf("trusted handshake: server=%v client=%v", serverErr, clientErr)
	}
	serverErr, clientErr = handshake(t, server.ServerTLS([]string{client.ID}), client.ClientTLS(strings.Repeat("0", 64)))
	if clientErr == nil {
		t.Fatalf("client accepted wrong server pin: server=%v", serverErr)
	}
	serverErr, clientErr = handshake(t, server.ServerTLS(nil), client.ClientTLS(server.ID))
	if serverErr == nil || clientErr == nil {
		t.Fatalf("server accepted unknown client: server=%v client=%v", serverErr, clientErr)
	}
	noCertificate := client.ClientTLS(server.ID)
	noCertificate.Certificates = nil
	serverErr, clientErr = handshake(t, server.ServerTLS([]string{client.ID}), noCertificate)
	if serverErr == nil || clientErr == nil {
		t.Fatalf("server accepted missing certificate: server=%v client=%v", serverErr, clientErr)
	}
}

func TestRejectExpiredCertificate(t *testing.T) {
	i := newIdentity(t)
	leaf := *i.Certificate.Leaf
	leaf.NotAfter = time.Now().Add(-time.Hour)
	if err := verifyPeer(tls.ConnectionState{PeerCertificates: []*x509.Certificate{&leaf}}, map[string]bool{i.ID: true}); err == nil {
		t.Fatal("accepted expired certificate")
	}
}
