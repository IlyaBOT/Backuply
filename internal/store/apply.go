package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"

	"github.com/IlyaBOT/Backuply/internal/model"
)

// Apply constructs a complete verified replacement in the destination
// directory. Failed fetches never expose a partial destination file. SQLite
// can lag the rename after a crash; the same-content branch repairs that index.
func (s *Store) Apply(ctx context.Context, folderID, root string, e model.Entry, fetch model.FetchBlock) (model.Stats, error) {
	var stats model.Stats
	if err := ValidateEntry(e); err != nil {
		return stats, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	if err := s.checkCapacity(ctx, folderID, e); err != nil {
		return stats, err
	}
	r, err := openFolder(root, folderID)
	if err != nil {
		return stats, err
	}
	defer r.Close()
	if err := checkComponents(r, e.Path, true); err != nil {
		return stats, err
	}
	info, statErr := r.Lstat(e.Path)
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return stats, statErr
	}
	if e.Kind == "directory" {
		if statErr != nil {
			_, indexErr := s.get(ctx, folderID, e.Path)
			if indexErr == nil {
				return stats, fmt.Errorf("%w (locally deleted): %s", ErrLocalChange, e.Path)
			}
			if !errors.Is(indexErr, sql.ErrNoRows) {
				return stats, indexErr
			}
		}
		if statErr == nil && !info.IsDir() {
			return stats, fmt.Errorf("%w: %s", ErrLocalChange, e.Path)
		}
		if err := ensureParents(r, e.Path); err != nil {
			return stats, err
		}
		if statErr != nil {
			// Keep owner access while children are installed. Directory permission
			// synchronization needs a finalization phase and is deferred.
			if err := r.Mkdir(e.Path, os.FileMode(e.Mode)|0700); err != nil {
				return stats, err
			}
			if err := syncDir(r, path.Dir(e.Path)); err != nil {
				return stats, err
			}
		}
		return stats, s.put(ctx, folderID, e)
	}
	var current model.Entry
	var old *os.File
	if statErr == nil {
		if !info.Mode().IsRegular() {
			return stats, fmt.Errorf("%w: %s", ErrLocalChange, e.Path)
		}
		current, err = fingerprint(ctx, r, e.Path)
		if err != nil {
			return stats, err
		}
		if current.Hash == e.Hash {
			if !slices.Equal(current.Blocks, e.Blocks) {
				return stats, errors.New("blocks do not match file checksum")
			}
			// Avoid trusting the index: fingerprint checked actual on-disk bytes.
			f, err := r.Open(e.Path)
			if err != nil {
				return stats, err
			}
			err = f.Chmod(os.FileMode(e.Mode))
			closeErr := f.Close()
			if err != nil {
				return stats, err
			}
			if closeErr != nil {
				return stats, closeErr
			}
			stats.BytesReused = e.Size
			return stats, s.put(ctx, folderID, e)
		}
		indexed, indexErr := s.get(ctx, folderID, e.Path)
		if errors.Is(indexErr, sql.ErrNoRows) || (indexErr == nil && (indexed.Kind != "file" || indexed.Hash != current.Hash)) {
			return stats, fmt.Errorf("%w: %s", ErrLocalChange, e.Path)
		}
		if indexErr != nil {
			return stats, indexErr
		}
		old, err = r.Open(e.Path)
		if err != nil {
			return stats, err
		}
		defer old.Close()
	} else {
		// A local deletion is also a local edit, not permission to restore it.
		_, indexErr := s.get(ctx, folderID, e.Path)
		if indexErr == nil {
			return stats, fmt.Errorf("%w (locally deleted): %s", ErrLocalChange, e.Path)
		}
		if !errors.Is(indexErr, sql.ErrNoRows) {
			return stats, indexErr
		}
	}
	if err := ensureParents(r, e.Path); err != nil {
		return stats, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return stats, err
	}
	tmp := path.Join(path.Dir(e.Path), tempPrefix+hex.EncodeToString(nonce[:]))
	out, err := r.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return stats, err
	}
	defer func() { out.Close(); r.Remove(tmp) }()
	blocks := make(map[string]model.Block, len(current.Blocks))
	for _, b := range current.Blocks {
		blocks[b.Hash] = b
	}
	full := sha256.New()
	for _, b := range e.Blocks {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		var data []byte
		if reuse, ok := blocks[b.Hash]; old != nil && ok && reuse.Size == b.Size {
			buf := make([]byte, b.Size)
			if _, err := old.ReadAt(buf, reuse.Offset); err == nil && hashBytes(buf) == b.Hash {
				data = buf
				stats.BytesReused += int64(len(buf))
			}
		}
		if data == nil {
			if fetch == nil {
				return stats, errors.New("missing block fetcher")
			}
			data, err = fetch(ctx, b)
			if err != nil {
				return stats, err
			}
			if len(data) != b.Size || hashBytes(data) != b.Hash {
				return stats, errors.New("received corrupt block")
			}
			stats.BytesReceived += int64(len(data))
		}
		if _, err := out.Write(data); err != nil {
			return stats, err
		}
		full.Write(data)
	}
	if hex.EncodeToString(full.Sum(nil)) != e.Hash {
		return stats, errors.New("file checksum mismatch")
	}
	if err := out.Chmod(os.FileMode(e.Mode)); err != nil {
		return stats, err
	}
	if err := out.Sync(); err != nil {
		return stats, err
	}
	if err := out.Close(); err != nil {
		return stats, err
	}
	if err := CheckFolder(root, folderID); err != nil {
		return stats, err
	}
	if err := checkMarker(r, folderID); err != nil {
		return stats, err
	}
	if err := checkComponents(r, e.Path, true); err != nil {
		return stats, err
	}
	// Recheck immediately before rename: preserve edits made during downloads.
	if old != nil {
		latest, err := fingerprint(ctx, r, e.Path)
		if err != nil {
			return stats, err
		}
		if latest.Hash != current.Hash {
			return stats, fmt.Errorf("%w: %s", ErrLocalChange, e.Path)
		}
	} else if _, err := r.Lstat(e.Path); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return stats, err
		}
		return stats, fmt.Errorf("%w: %s", ErrLocalChange, e.Path)
	}
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	if err := r.Rename(tmp, e.Path); err != nil {
		return stats, err
	}
	if err := syncDir(r, path.Dir(e.Path)); err != nil {
		return stats, err
	}
	if err := s.put(ctx, folderID, e); err != nil {
		return stats, err
	}
	stats.Files = 1
	return stats, nil
}
