package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IlyaBOT/Backuply/internal/model"
)

func cert(t *testing.T) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
}

func pinnedConfig(local tls.Certificate, peer tls.Certificate, server bool) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{local}, InsecureSkipVerify: true}
	if server {
		cfg.ClientAuth = tls.RequireAnyClientCert
	}
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) != 1 || !bytes.Equal(state.PeerCertificates[0].Raw, peer.Certificate[0]) {
			return errors.New("untrusted peer")
		}
		return nil
	}
	return cfg
}

type testBackend struct {
	entries   []model.Entry
	data      []byte
	peer      string
	mu        sync.Mutex
	calls     int
	blockList bool
	entered   chan struct{}
}

func (b *testBackend) List(ctx context.Context, peer, folder string) ([]model.Entry, error) {
	if b.blockList {
		close(b.entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if peer != b.peer || folder != "projects" {
		return nil, errors.New("access denied")
	}
	return b.entries, nil
}

func (b *testBackend) ReadBlock(_ context.Context, peer, folder, path, hash string, block model.Block) ([]byte, error) {
	if peer != b.peer || folder != "projects" || path != "a.bin" || hash != b.entries[0].Hash {
		return nil, errors.New("access denied")
	}
	return b.data, nil
}

func startServer(t *testing.T, backend *testBackend) (string, *tls.Config, context.CancelFunc, <-chan error) {
	t.Helper()
	serverCert, clientCert := cert(t), cert(t)
	fingerprint := sha256.Sum256(clientCert.Certificate[0])
	backend.peer = hex.EncodeToString(fingerprint[:])
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, listener, pinnedConfig(serverCert, clientCert, true), backend) }()
	t.Cleanup(cancel)
	return listener.Addr().String(), pinnedConfig(clientCert, serverCert, false), cancel, done
}

func TestPersistentSessionAndBlocks(t *testing.T) {
	data := bytes.Repeat([]byte{0, 255, 128, 42}, 10000)
	hash := sha256.Sum256(data)
	block := model.Block{Size: len(data), Hash: hex.EncodeToString(hash[:])}
	b := &testBackend{data: data, entries: []model.Entry{{Path: "a.bin", Kind: "file", Size: int64(len(data)), Hash: block.Hash, Blocks: []model.Block{block}}}}
	address, config, cancel, done := startServer(t, b)
	c, err := Dial(context.Background(), address, config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 3 {
		entries, err := c.List(context.Background(), "projects")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(entries, b.entries) {
			t.Fatalf("entries differ: %#v", entries)
		}
		got, err := c.ReadBlock(context.Background(), "projects", "a.bin", block.Hash, block)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatal("binary block differs")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not close active session")
	}
	if _, err := c.List(context.Background(), "projects"); err == nil {
		t.Fatal("closed session accepted request")
	}
}

func TestFrameLimitsAndTruncation(t *testing.T) {
	for _, size := range []uint32{0, maxControl + 1, ^uint32(0)} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		if _, err := readFrame(bytes.NewReader(header[:]), maxControl); err == nil {
			t.Fatalf("size %d accepted", size)
		}
	}
	for _, data := range [][]byte{{0, 0}, {0, 0, 0, 3, 'a'}} {
		if _, err := readFrame(bytes.NewReader(data), maxControl); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("want truncated frame, got %v", err)
		}
	}
	var encoded bytes.Buffer
	if err := writeFrame(&encoded, []byte("ok"), 2); err != nil {
		t.Fatal(err)
	}
	got, err := readFrame(&encoded, 2)
	if err != nil || string(got) != "ok" {
		t.Fatalf("round trip: %q %v", got, err)
	}
}

func TestIndexStreamsBeyondControlFrameLimit(t *testing.T) {
	entries := make([]model.Entry, 4500)
	for i := range entries {
		entries[i] = model.Entry{Path: strings.Repeat("a", 1000), Kind: "directory"}
	}
	b := &testBackend{entries: entries}
	address, config, cancel, done := startServer(t, b)
	c, err := Dial(context.Background(), address, config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	got, err := c.List(context.Background(), "projects")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(entries, got) {
		t.Fatal("streamed index differs")
	}
	if _, err := c.List(context.Background(), "private"); err == nil {
		t.Fatal("unauthorized folder accepted")
	}
	cancel()
	<-done
}

func TestRejectUntrustedPeer(t *testing.T) {
	address, cfg, cancel, done := startServer(t, &testBackend{})
	cfg.Certificates = []tls.Certificate{cert(t)}
	if c, err := Dial(context.Background(), address, cfg); err == nil {
		c.Close()
		t.Fatal("untrusted certificate accepted")
	}
	cancel()
	<-done
}

func TestCancellationInterruptsRequest(t *testing.T) {
	b := &testBackend{blockList: true, entered: make(chan struct{})}
	address, config, cancelServer, serverDone := startServer(t, b)
	c, err := Dial(context.Background(), address, config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := c.List(ctx, "projects"); done <- err }()
	select {
	case <-b.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("backend never entered")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled request remained blocked")
	}
	cancelServer()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backend context not canceled")
	}
}

func TestRejectCorruptBlock(t *testing.T) {
	hash := sha256.Sum256([]byte("correct"))
	block := model.Block{Size: 7, Hash: hex.EncodeToString(hash[:])}
	b := &testBackend{data: []byte("corrupt"), entries: []model.Entry{{Hash: block.Hash}}}
	address, config, cancel, done := startServer(t, b)
	c, err := Dial(context.Background(), address, config)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.ReadBlock(context.Background(), "projects", "a.bin", block.Hash, block); err == nil {
		t.Fatal("corrupt block accepted")
	}
	if _, err := c.List(context.Background(), "projects"); err == nil {
		t.Fatal("poisoned session was reused")
	}
	cancel()
	<-done
}

func TestRejectProtocolAndMalformedControl(t *testing.T) {
	address, config, cancel, done := startServer(t, &testBackend{})
	for _, payload := range [][]byte{[]byte(`{"type":"hello","version":999}`), []byte(`{"type":`)} {
		conn, err := tls.Dial("tcp", address, config)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		if err := writeFrame(conn, payload, maxControl); err != nil {
			t.Fatal(err)
		}
		var one [1]byte
		if _, err := conn.Read(one[:]); err == nil {
			t.Fatal("invalid hello accepted")
		}
		conn.Close()
	}
	cancel()
	<-done
}

func TestRejectInsecureTLS(t *testing.T) {
	for _, cfg := range []*tls.Config{nil, {}, {MinVersion: tls.VersionTLS13, InsecureSkipVerify: true}} {
		if _, err := Dial(context.Background(), "127.0.0.1:1", cfg); err == nil {
			t.Fatal("insecure configuration accepted")
		}
	}
	if err := validateTLS(&tls.Config{MinVersion: tls.VersionTLS13}, true); err == nil {
		t.Fatal("anonymous client TLS accepted")
	}
}
