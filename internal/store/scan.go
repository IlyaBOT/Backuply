package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/IlyaBOT/Backuply/internal/model"
)

// Scan replaces the folder index only after a complete successful walk. A
// missing mount/marker, unreadable file, or unstable file leaves it untouched.
func (s *Store) Scan(ctx context.Context, folderID, root string) ([]model.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := openFolder(root, folderID)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	entries := make([]model.Entry, 0)
	manifestBytes := 0
	err = fs.WalkDir(r.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		base := path.Base(name)
		if base == markerName || strings.HasPrefix(base, tempPrefix) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if err := checkComponents(r, name, false); err != nil {
			return err
		}
		info, err := r.Lstat(name)
		if err != nil {
			return err
		}
		var e model.Entry
		if info.IsDir() {
			e = model.Entry{Path: name, Kind: "directory", Mode: uint32(info.Mode().Perm())}
		} else if info.Mode().IsRegular() {
			e, err = fingerprint(ctx, r, name)
			if err != nil {
				return fmt.Errorf("scan %q: %w", name, err)
			}
		} else {
			return fmt.Errorf("unsupported file type at %q", name)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		manifestBytes += len(raw) + 1
		if len(entries) >= MaxEntries || manifestBytes > MaxManifestBytes-2 {
			return fmt.Errorf("folder manifest exceeds limits")
		}
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Reopen by configured path too, detecting a mount/root replaced during scan.
	if err := CheckFolder(root, folderID); err != nil {
		return nil, err
	}
	if err := checkMarker(r, folderID); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM entries WHERE folder=?", folderID); err != nil {
		return nil, err
	}
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO entries(folder,path,manifest) VALUES(?,?,?)")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	for _, e := range entries {
		raw, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		if _, err := stmt.ExecContext(ctx, folderID, e.Path, raw); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ReadBlock serves only an exact block from the current indexed manifest.
func (s *Store) ReadBlock(ctx context.Context, folderID, root, name, entryHash string, b model.Block) ([]byte, error) {
	if err := validPath(name); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e, err := s.get(ctx, folderID, name)
	if err != nil {
		return nil, err
	}
	if err := ValidateEntry(e); err != nil {
		return nil, err
	}
	if e.Kind != "file" || e.Hash != entryHash || b.Offset < 0 || b.Offset%model.BlockSize != 0 {
		return nil, fmt.Errorf("stale or invalid block request")
	}
	i := b.Offset / model.BlockSize
	if i >= int64(len(e.Blocks)) || e.Blocks[i] != b {
		return nil, fmt.Errorf("block not in indexed manifest")
	}
	r, err := openFolder(root, folderID)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	if err := checkComponents(r, name, false); err != nil {
		return nil, err
	}
	f, err := r.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != e.Size {
		return nil, fmt.Errorf("source file changed")
	}
	data := make([]byte, b.Size)
	if _, err := f.ReadAt(data, b.Offset); err != nil {
		return nil, err
	}
	if hashBytes(data) != b.Hash {
		return nil, fmt.Errorf("source block changed")
	}
	return data, nil
}
