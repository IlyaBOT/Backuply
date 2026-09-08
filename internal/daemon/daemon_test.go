package daemon

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IlyaBOT/Backuply/internal/config"
	"github.com/IlyaBOT/Backuply/internal/identity"
	"github.com/IlyaBOT/Backuply/internal/model"
	"github.com/IlyaBOT/Backuply/internal/store"
	"github.com/IlyaBOT/Backuply/internal/transport"
)

func nodeConfig(t *testing.T) (config.Config, *identity.Identity) {
	t.Helper()
	// Keep the Unix control socket below the platform sockaddr_un path limit.
	dir, err := os.MkdirTemp("", "backuply-daemon-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	c := config.Config{Listen: "127.0.0.1:0", StateDir: filepath.Join(dir, "state"), ScanInterval: 100 * time.Millisecond, Peers: map[string]config.Peer{}, Folders: map[string]config.Folder{}}
	id, err := identity.LoadOrCreate(c.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	return c, id
}

func folder(t *testing.T, cfg *config.Config, id, source string, peers ...string) string {
	t.Helper()
	path := filepath.Join(filepath.Dir(cfg.StateDir), id)
	if err := store.InitFolder(path, id); err != nil {
		t.Fatal(err)
	}
	cfg.Folders[id] = config.Folder{ID: id, Path: path, Source: source, Peers: peers}
	return path
}

func eventually(t *testing.T, description string, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if predicate() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", description)
		case <-tick.C:
		}
	}
}

func startNode(t *testing.T, cfg config.Config) (*Daemon, func()) {
	t.Helper()
	d, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("daemon Run: %v", err)
				}
				if err := d.Close(); err != nil {
					t.Errorf("daemon Close: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("daemon failed to stop within 3 seconds")
			}
		})
	}
	t.Cleanup(stop)
	eventually(t, "daemon listener", func() bool { return d.Status().Running })
	return d, stop
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	// Atomic source updates avoid intentionally racing a half-written source file.
	tmp := filepath.Join(filepath.Dir(path), ".backuply-tmp-test-write")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func TestDaemonReplicationDeltaAndLocalEditProtection(t *testing.T) {
	sourceCfg, sourceID := nodeConfig(t)
	receiverCfg, receiverID := nodeConfig(t)
	sourceCfg.Peers["receiver"] = config.Peer{Name: "receiver", Address: "127.0.0.1:24800", DeviceID: receiverID.ID}
	sourceRoot := folder(t, &sourceCfg, "projects", "local", "receiver")
	data := append(bytes.Repeat([]byte{1}, model.BlockSize), bytes.Repeat([]byte{2}, model.BlockSize)...)
	data = append(data, bytes.Repeat([]byte{3}, model.BlockSize)...)
	if err := os.Mkdir(filepath.Join(sourceRoot, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(sourceRoot, "nested", "data.bin"), data)
	writeFile(t, filepath.Join(sourceRoot, "tiny.txt"), []byte("small file\n"))
	source, _ := startNode(t, sourceCfg)
	receiverCfg.Peers["source"] = config.Peer{Name: "source", Address: source.Status().Listen, DeviceID: sourceID.ID}
	receiverRoot := folder(t, &receiverCfg, "projects", "source", "source")
	receiver, stopReceiver := startNode(t, receiverCfg)
	expectedBytes := int64(len(data) + len("small file\n"))
	eventually(t, "initial file transfer", func() bool {
		s := receiver.Status().Folders["projects"]
		return s.LastError == "" && s.Entries == 3 && s.BytesReceived == expectedBytes
	})
	got, err := os.ReadFile(filepath.Join(receiverRoot, "nested", "data.bin"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("initial content mismatch: %v", err)
	}
	first := receiver.Status().Folders["projects"]
	eventually(t, "unchanged rescan", func() bool { return receiver.Status().Folders["projects"].LastSuccess.After(first.LastSuccess) })
	if got := receiver.Status().Folders["projects"].BytesReceived; got != expectedBytes {
		t.Fatalf("unchanged files downloaded again: %d", got)
	}
	updated := bytes.Clone(data)
	updated[model.BlockSize+37] ^= 0xff
	writeFile(t, filepath.Join(sourceRoot, "nested", "data.bin"), updated)
	eventually(t, "single-block delta", func() bool {
		got, err := os.ReadFile(filepath.Join(receiverRoot, "nested", "data.bin"))
		return err == nil && bytes.Equal(got, updated) && receiver.Status().Folders["projects"].BytesReceived == expectedBytes+model.BlockSize
	})
	status, err := QueryStatus(context.Background(), receiverCfg.StateDir)
	if err != nil || status.DeviceID != receiverID.ID || !status.Running {
		t.Fatalf("control status: %+v, %v", status, err)
	}
	if status.Folders["projects"].BytesReused < 2*model.BlockSize {
		t.Fatal("unchanged blocks were not reused")
	}
	local := []byte("receiver's uncommitted work must survive\n")
	writeFile(t, filepath.Join(receiverRoot, "nested", "data.bin"), local)
	eventually(t, "local change protection", func() bool { return strings.Contains(receiver.Status().Folders["projects"].LastError, "local change") })
	got, err = os.ReadFile(filepath.Join(receiverRoot, "nested", "data.bin"))
	if err != nil || !bytes.Equal(got, local) {
		t.Fatalf("receiver local edits lost: %v", err)
	}
	stopReceiver()
	if receiver.Status().Running {
		t.Fatal("shutdown left Running set")
	}
	if _, err := QueryStatus(context.Background(), receiverCfg.StateDir); err == nil {
		t.Fatal("control server remains after shutdown")
	}
}

func TestDaemonFolderACLAndIdentityTrust(t *testing.T) {
	cfg, serverID := nodeConfig(t)
	_, trustedID := nodeConfig(t)
	_, unknownID := nodeConfig(t)
	cfg.Peers["trusted"] = config.Peer{Name: "trusted", Address: "127.0.0.1:24800", DeviceID: trustedID.ID}
	folder(t, &cfg, "shared", "local", "trusted")
	secret := folder(t, &cfg, "secret", "local")
	writeFile(t, filepath.Join(secret, "private.txt"), []byte("private"))
	d, _ := startNode(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := transport.Dial(ctx, d.Status().Listen, trustedID.ClientTLS(serverID.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.List(ctx, "shared"); err != nil {
		t.Fatalf("authorized folder denied: %v", err)
	}
	if _, err := client.List(ctx, "secret"); err == nil {
		t.Fatal("trusted peer accessed an unshared folder")
	}
	client, err = transport.Dial(ctx, d.Status().Listen, trustedID.ClientTLS(serverID.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.List(ctx, "unknown"); err == nil {
		t.Fatal("unknown folder was accepted")
	}
	entries, err := d.store.List(ctx, "secret")
	if err != nil || len(entries) != 1 {
		t.Fatalf("private fixture index: %v, %v", entries, err)
	}
	client, err = transport.Dial(ctx, d.Status().Listen, trustedID.ClientTLS(serverID.ID))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	entry := entries[0]
	if _, err := client.ReadBlock(ctx, "secret", entry.Path, entry.Hash, entry.Blocks[0]); err == nil {
		t.Fatal("trusted peer fetched a block from an unshared folder")
	}
	if client, err := transport.Dial(ctx, d.Status().Listen, unknownID.ClientTLS(serverID.ID)); err == nil {
		client.Close()
		t.Fatal("untrusted device connected")
	}
}

func TestDaemonStateLockAndRelease(t *testing.T) {
	cfg, _ := nodeConfig(t)
	_, stop := startNode(t, cfg)
	if second, err := New(cfg, nil); err == nil {
		second.Close()
		t.Fatal("two daemons opened the same state directory")
	}
	stop()
	restarted, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("state lock not released: %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
}
