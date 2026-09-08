package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/IlyaBOT/Backuply/internal/model"
)

func testStore(t *testing.T) (*Store, string, string) {
	t.Helper()
	state := t.TempDir()
	root := t.TempDir()
	s, err := Open(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := InitFolder(root, "projects"); err != nil {
		t.Fatal(err)
	}
	return s, root, state
}

func write(t *testing.T, root, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func scanFile(t *testing.T, s *Store, root string) model.Entry {
	t.Helper()
	entries, err := s.Scan(context.Background(), "projects", root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Kind == "file" {
			return e
		}
	}
	t.Fatal("no file in scan")
	return model.Entry{}
}

func fetchFrom(s *Store, root string, e model.Entry) model.FetchBlock {
	return func(ctx context.Context, b model.Block) ([]byte, error) {
		return s.ReadBlock(ctx, "projects", root, e.Path, e.Hash, b)
	}
}

func TestDeltaReuseAndReopen(t *testing.T) {
	ctx := context.Background()
	src, source, _ := testStore(t)
	dst, dest, state := testStore(t)
	data := append(bytes.Repeat([]byte("a"), model.BlockSize), bytes.Repeat([]byte("b"), model.BlockSize)...)
	data = append(data, bytes.Repeat([]byte("c"), model.BlockSize)...)
	write(t, source, "example", data)
	e := scanFile(t, src, source)
	stats, err := dst.Apply(ctx, "projects", dest, e, fetchFrom(src, source, e))
	if err != nil {
		t.Fatal(err)
	}
	if stats.BytesReceived != int64(len(data)) || stats.Files != 1 {
		t.Fatalf("initial stats: %+v", stats)
	}
	data[model.BlockSize+42] = 'z'
	write(t, source, "example", data)
	e = scanFile(t, src, source)
	stats, err = dst.Apply(ctx, "projects", dest, e, fetchFrom(src, source, e))
	if err != nil {
		t.Fatal(err)
	}
	if stats.BytesReceived != model.BlockSize || stats.BytesReused != 2*model.BlockSize {
		t.Fatalf("delta stats: %+v", stats)
	}
	got, err := os.ReadFile(filepath.Join(dest, "example"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("incorrect destination data")
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	dst, err = Open(state)
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	stats, err = dst.Apply(ctx, "projects", dest, e, func(context.Context, model.Block) ([]byte, error) {
		t.Fatal("unchanged file downloaded")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Files != 0 || stats.BytesReceived != 0 || stats.BytesReused != int64(len(data)) {
		t.Fatalf("unchanged stats: %+v", stats)
	}
	listed, err := dst.List(ctx, "projects")
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Hash != e.Hash {
		t.Fatalf("reopened index: %+v", listed)
	}
}

func TestLocalChangesPreserved(t *testing.T) {
	for _, scenario := range []string{"unindexed", "modified", "deleted", "during-download"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			src, source, _ := testStore(t)
			dst, dest, _ := testStore(t)
			write(t, source, "file", []byte("original"))
			e := scanFile(t, src, source)
			if scenario != "unindexed" {
				if _, err := dst.Apply(ctx, "projects", dest, e, fetchFrom(src, source, e)); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "deleted" {
				if err := os.Remove(filepath.Join(dest, "file")); err != nil {
					t.Fatal(err)
				}
			} else if scenario != "during-download" {
				write(t, dest, "file", []byte("local"))
			}
			write(t, source, "file", []byte("remote"))
			e = scanFile(t, src, source)
			fetch := fetchFrom(src, source, e)
			if scenario == "during-download" {
				fetch = func(ctx context.Context, b model.Block) ([]byte, error) {
					write(t, dest, "file", []byte("local"))
					return src.ReadBlock(ctx, "projects", source, e.Path, e.Hash, b)
				}
			}
			if _, err := dst.Apply(ctx, "projects", dest, e, fetch); !errors.Is(err, ErrLocalChange) {
				t.Fatalf("expected ErrLocalChange, got %v", err)
			}
			got, err := os.ReadFile(filepath.Join(dest, "file"))
			if scenario == "deleted" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("local deletion restored: %v", err)
				}
			} else if err != nil || string(got) != "local" {
				t.Fatalf("local change lost: %q, %v", got, err)
			}
		})
	}
}

func TestCorruptionNeverReplacesFile(t *testing.T) {
	ctx := context.Background()
	src, source, _ := testStore(t)
	dst, dest, _ := testStore(t)
	write(t, source, "file", []byte("old"))
	old := scanFile(t, src, source)
	if _, err := dst.Apply(ctx, "projects", dest, old, fetchFrom(src, source, old)); err != nil {
		t.Fatal(err)
	}
	write(t, source, "file", []byte("new"))
	e := scanFile(t, src, source)
	if _, err := dst.Apply(ctx, "projects", dest, e, func(context.Context, model.Block) ([]byte, error) { return []byte("bad"), nil }); err == nil {
		t.Fatal("corrupt block accepted")
	}
	bad := e
	bad.Hash = hashBytes([]byte("incorrect final hash"))
	if _, err := dst.Apply(ctx, "projects", dest, bad, fetchFrom(src, source, e)); err == nil {
		t.Fatal("corrupt file hash accepted")
	}
	got, err := os.ReadFile(filepath.Join(dest, "file"))
	if err != nil || string(got) != "old" {
		t.Fatalf("old content lost: %q %v", got, err)
	}
	names, err := os.ReadDir(dest)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("temporary file leaked: %v", names)
	}
}

func TestConfinementAndManifestValidation(t *testing.T) {
	ctx := context.Background()
	src, source, _ := testStore(t)
	dst, dest, _ := testStore(t)
	write(t, source, "file", []byte("content"))
	e := scanFile(t, src, source)
	for _, name := range []string{"../escape", "/absolute", "a/../b", "a\\b", ".", ".backuply-folder", "a/.backuply-tmp-malicious", "a//b"} {
		bad := e
		bad.Path = name
		if _, err := dst.Apply(ctx, "projects", dest, bad, fetchFrom(src, source, e)); err == nil {
			t.Errorf("accepted path %q", name)
		}
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dest, "link")); err != nil {
		t.Fatal(err)
	}
	bad := e
	bad.Path = "link/escape"
	if _, err := dst.Apply(ctx, "projects", dest, bad, fetchFrom(src, source, e)); err == nil {
		t.Fatal("symlink traversal accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("escaped root")
	}
	bad = e
	bad.Blocks = slices.Clone(e.Blocks)
	bad.Blocks[0].Size = model.BlockSize + 1
	if err := ValidateEntry(bad); err == nil {
		t.Fatal("invalid block size accepted")
	}
	bad = e
	bad.Size = MaxFileSize + 1
	if err := ValidateEntry(bad); err == nil {
		t.Fatal("oversized file accepted")
	}
	bad = e
	bad.Mode = 04755
	if err := ValidateEntry(bad); err == nil {
		t.Fatal("setuid accepted")
	}
	block := e.Blocks[0]
	block.Offset++
	if _, err := src.ReadBlock(ctx, "projects", source, e.Path, e.Hash, block); err == nil {
		t.Fatal("unindexed block accepted")
	}
}

func TestScanFailureKeepsIndexAndMarkerPauses(t *testing.T) {
	ctx := context.Background()
	s, root, _ := testStore(t)
	write(t, root, "file", []byte("content"))
	original := scanFile(t, s, root)
	if err := os.Symlink("file", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Scan(ctx, "projects", root); err == nil {
		t.Fatal("symlink silently omitted")
	}
	entries, err := s.List(ctx, "projects")
	if err != nil || len(entries) != 1 || entries[0].Hash != original.Hash {
		t.Fatalf("failed scan altered index: %v %v", entries, err)
	}
	if err := os.Remove(filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, markerName)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Scan(ctx, "projects", root); err == nil {
		t.Fatal("scan without marker accepted")
	}
	if _, err := s.ReadBlock(ctx, "projects", root, original.Path, original.Hash, original.Blocks[0]); err == nil {
		t.Fatal("read without marker accepted")
	}
	if _, err := s.Apply(ctx, "projects", root, original, nil); err == nil {
		t.Fatal("apply without marker accepted")
	}
	if err := InitFolder(root, "other"); err != nil {
		t.Fatal(err)
	}
	if err := CheckFolder(root, "projects"); err == nil {
		t.Fatal("wrong folder marker accepted")
	}
	if err := InitFolder(root, "projects"); err == nil {
		t.Fatal("existing marker overwritten")
	}
}

func TestEmptyFilesDirectoriesAndCrashReconciliation(t *testing.T) {
	ctx := context.Background()
	src, source, _ := testStore(t)
	dst, dest, _ := testStore(t)
	if err := os.Mkdir(filepath.Join(source, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	write(t, source, "nested/empty", nil)
	entries, err := src.Scan(ctx, "projects", source)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if _, err := dst.Apply(ctx, "projects", dest, e, fetchFrom(src, source, e)); err != nil {
			t.Fatal(err)
		}
	}
	write(t, source, "nested/empty", []byte("renamed-before-db-commit"))
	e := scanFile(t, src, source)
	// Reproduce a crash window after rename and before SQLite update.
	write(t, dest, "nested/empty", []byte("renamed-before-db-commit"))
	if _, err := dst.Apply(ctx, "projects", dest, e, nil); err != nil {
		t.Fatal(err)
	}
	indexed, err := dst.get(ctx, "projects", e.Path)
	if err != nil || indexed.Hash != e.Hash {
		t.Fatalf("stale index not repaired: %v", err)
	}
	write(t, source, ".backuply-tmp-orphan", []byte("partial"))
	entries, err = src.Scan(ctx, "projects", source)
	if err != nil || len(entries) != 2 {
		t.Fatalf("orphan temp indexed: %v %v", entries, err)
	}
	if err := os.Remove(filepath.Join(source, "nested/empty")); err != nil {
		t.Fatal(err)
	}
	entries, err = src.Scan(ctx, "projects", source)
	if err != nil || len(entries) != 1 {
		t.Fatalf("deleted source remained indexed: %v %v", entries, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "nested/empty")); err != nil {
		t.Fatal("source deletion affected receiver")
	}
}

func TestDirectoryLocalDeletionAndIndexBudget(t *testing.T) {
	ctx := context.Background()
	s, root, _ := testStore(t)
	dir := model.Entry{Path: "directory", Kind: "directory", Mode: 0500}
	if _, err := s.Apply(ctx, "projects", root, dir, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, dir.Path))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0700 != 0700 {
		t.Fatal("created directory cannot receive children")
	}
	if err := os.Remove(filepath.Join(root, dir.Path)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(ctx, "projects", root, dir, nil); !errors.Is(err, ErrLocalChange) {
		t.Fatalf("local directory deletion not protected: %v", err)
	}
	// Simulate a folder at its budget without allocating a 64 MiB test fixture.
	if _, err := s.db.Exec("UPDATE folder_usage SET bytes=? WHERE folder=?", MaxManifestBytes-2, "projects"); err != nil {
		t.Fatal(err)
	}
	e := model.Entry{Path: "overflow", Kind: "file", Mode: 0600, Hash: hashBytes(nil)}
	if _, err := s.Apply(ctx, "projects", root, e, nil); err == nil {
		t.Fatal("index budget ignored")
	}
	if _, err := os.Stat(filepath.Join(root, e.Path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file created before budget rejection")
	}
}

func TestIndexedSourceBlockChangesAndCancellation(t *testing.T) {
	ctx := context.Background()
	s, root, _ := testStore(t)
	write(t, root, "file", []byte("before"))
	e := scanFile(t, s, root)
	write(t, root, "file", []byte("after!"))
	if _, err := s.ReadBlock(ctx, "projects", root, e.Path, e.Hash, e.Blocks[0]); err == nil {
		t.Fatal("changed source block accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := s.Scan(cancelled, "projects", root); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan: %v", err)
	}
	indexed, err := s.get(ctx, "projects", e.Path)
	if err != nil || indexed.Hash != e.Hash {
		t.Fatalf("cancelled scan modified index: %v", err)
	}
}
