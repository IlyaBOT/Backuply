package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/IlyaBOT/Backuply/internal/model"
)

func validPath(name string) error {
	if name == "." || len(name) > 4096 || !fs.ValidPath(name) || strings.ContainsAny(name, "\\:\x00") {
		return fmt.Errorf("invalid relative path %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == markerName || strings.HasPrefix(part, tempPrefix) {
			return fmt.Errorf("reserved path %q", name)
		}
	}
	return nil
}

// ValidateEntry checks the complete fixed-block layout before allocation or I/O.
func ValidateEntry(e model.Entry) error {
	if err := validPath(e.Path); err != nil {
		return err
	}
	if e.Mode & ^uint32(0777) != 0 {
		return errors.New("unsupported file permissions")
	}
	if e.Kind == "directory" {
		if e.Size != 0 || e.Hash != "" || len(e.Blocks) != 0 {
			return errors.New("invalid directory metadata")
		}
		return nil
	}
	if e.Kind != "file" || e.Size < 0 || e.Size > MaxFileSize || !validHash(e.Hash) {
		return errors.New("invalid file metadata")
	}
	if int64(len(e.Blocks)) != (e.Size+model.BlockSize-1)/model.BlockSize {
		return errors.New("invalid block count")
	}
	var offset int64
	for _, b := range e.Blocks {
		size := min(int64(model.BlockSize), e.Size-offset)
		if b.Offset != offset || int64(b.Size) != size || !validHash(b.Hash) {
			return errors.New("invalid block layout")
		}
		offset += size
	}
	return nil
}

func validHash(h string) bool {
	if len(h) != 64 || strings.ToLower(h) != h {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

func hashBytes(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func InitFolder(root, folderID string) error {
	if folderID == "" || len(folderID) > 256 || strings.ContainsAny(folderID, "\r\n\x00") {
		return errors.New("invalid folder ID")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	f, err := r.OpenFile(markerName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, fs.ErrExist) {
		return checkMarker(r, folderID)
	}
	if err != nil {
		return err
	}
	if _, err = f.WriteString(folderID + "\n"); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return syncDir(r, ".")
}

func CheckFolder(root, folderID string) error {
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	return checkMarker(r, folderID)
}

func checkMarker(r *os.Root, folderID string) error {
	info, err := r.Lstat(markerName)
	if err != nil {
		return fmt.Errorf("folder marker unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 257 {
		return errors.New("invalid folder marker")
	}
	f, err := r.Open(markerName)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 258))
	if err != nil {
		return err
	}
	if string(b) != folderID+"\n" {
		return errors.New("folder marker ID mismatch")
	}
	return nil
}

func openFolder(root, folderID string) (*os.Root, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	if err := checkMarker(r, folderID); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

// Reject symlinks and special files in every existing component. os.Root also
// enforces confinement if another process races the checks with a symlink swap.
func checkComponents(r *os.Root, name string, allowMissing bool) error {
	if err := validPath(name); err != nil {
		return err
	}
	parts := strings.Split(name, "/")
	for i := range parts {
		info, err := r.Lstat(strings.Join(parts[:i+1], "/"))
		if errors.Is(err, fs.ErrNotExist) && allowMissing {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("unsupported filesystem object at %q", name)
		}
		if i < len(parts)-1 && !info.IsDir() {
			return fmt.Errorf("non-directory parent at %q", name)
		}
	}
	return nil
}

func fingerprint(ctx context.Context, r *os.Root, name string) (model.Entry, error) {
	e := model.Entry{Path: name, Kind: "file"}
	if err := checkComponents(r, name, false); err != nil {
		return e, err
	}
	f, err := r.Open(name)
	if err != nil {
		return e, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return e, err
	}
	if !before.Mode().IsRegular() || before.Size() > MaxFileSize {
		return e, errors.New("unsupported file type or size")
	}
	e.Mode = uint32(before.Mode().Perm())
	e.Size = before.Size()
	full := sha256.New()
	buf := make([]byte, model.BlockSize)
	for offset := int64(0); offset < e.Size; {
		if err := ctx.Err(); err != nil {
			return e, err
		}
		size := int(min(int64(model.BlockSize), e.Size-offset))
		if _, err := io.ReadFull(f, buf[:size]); err != nil {
			return e, err
		}
		full.Write(buf[:size])
		e.Blocks = append(e.Blocks, model.Block{Offset: offset, Size: size, Hash: hashBytes(buf[:size])})
		offset += int64(size)
	}
	after, err := f.Stat()
	if err != nil {
		return e, err
	}
	current, err := r.Lstat(name)
	if err != nil {
		return e, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, current) {
		return e, errors.New("file changed while reading")
	}
	e.Hash = hex.EncodeToString(full.Sum(nil))
	return e, nil
}

func syncDir(r *os.Root, name string) error {
	f, err := r.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func ensureParents(r *os.Root, name string) error {
	parent := path.Dir(name)
	if parent == "." {
		return nil
	}
	if err := checkComponents(r, parent, true); err != nil {
		return err
	}
	return r.MkdirAll(parent, 0700)
}
