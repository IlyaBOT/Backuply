// Package store maintains the local index and installs verified file versions.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/IlyaBOT/Backuply/internal/model"
	_ "modernc.org/sqlite"
)

const (
	MaxFileSize      int64 = 8 << 30
	MaxEntries             = 100000
	MaxManifestBytes       = 64 << 20
	markerName             = ".backuply-folder"
	tempPrefix             = ".backuply-tmp-"
)

var ErrLocalChange = errors.New("local change would be overwritten")

type Store struct {
	db *sql.DB
	mu sync.Mutex // Serialize index scans and file installation; reads remain available.
}

func Open(stateDir string) (*Store, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	name, err := filepath.Abs(filepath.Join(stateDir, "index.sqlite"))
	if err != nil {
		return nil, err
	}
	// Precreate privately; SQLite's WAL inherits the database permissions.
	f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: name}
	db, err := sql.Open("sqlite", u.String()+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	fail := func(err error) (*Store, error) { db.Close(); return nil, err }
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if version != 0 && version != 1 {
		return fail(fmt.Errorf("unsupported database schema version %d", version))
	}
	if _, err := db.Exec(fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS entries (folder TEXT NOT NULL, path TEXT NOT NULL, manifest BLOB NOT NULL, PRIMARY KEY(folder,path));
CREATE TABLE IF NOT EXISTS folder_usage (
 folder TEXT PRIMARY KEY, entries INTEGER NOT NULL CHECK(entries BETWEEN 0 AND %d),
 bytes INTEGER NOT NULL CHECK(bytes BETWEEN 0 AND %d)
);
CREATE TRIGGER IF NOT EXISTS entries_insert AFTER INSERT ON entries BEGIN
 INSERT INTO folder_usage(folder,entries,bytes) VALUES(new.folder,1,length(new.manifest)+1)
 ON CONFLICT(folder) DO UPDATE SET entries=entries+1,bytes=bytes+length(new.manifest)+1;
END;
CREATE TRIGGER IF NOT EXISTS entries_update AFTER UPDATE ON entries BEGIN
 UPDATE folder_usage SET bytes=bytes+length(new.manifest)-length(old.manifest) WHERE folder=new.folder;
END;
CREATE TRIGGER IF NOT EXISTS entries_delete AFTER DELETE ON entries BEGIN
 UPDATE folder_usage SET entries=entries-1,bytes=bytes-length(old.manifest)-1 WHERE folder=old.folder;
END;
INSERT INTO folder_usage(folder,entries,bytes)
 SELECT folder,count(*),sum(length(manifest)+1) FROM entries GROUP BY folder
 ON CONFLICT(folder) DO UPDATE SET entries=excluded.entries,bytes=excluded.bytes;
PRAGMA user_version=1;`, MaxEntries, MaxManifestBytes-2)); err != nil {
		return fail(err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) List(ctx context.Context, folderID string) ([]model.Entry, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT manifest FROM entries WHERE folder=? ORDER BY path", folderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := make([]model.Entry, 0)
	manifestBytes := 2
	for rows.Next() {
		var raw []byte
		var entry model.Entry
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		manifestBytes += len(raw) + 1
		if len(entries) >= MaxEntries || manifestBytes > MaxManifestBytes {
			return nil, errors.New("folder index exceeds manifest limits")
		}
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, err
		}
		if err := ValidateEntry(entry); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *Store) get(ctx context.Context, folderID, name string) (model.Entry, error) {
	var entry model.Entry
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT manifest FROM entries WHERE folder=? AND path=?", folderID, name).Scan(&raw)
	if err != nil {
		return entry, err
	}
	err = json.Unmarshal(raw, &entry)
	return entry, err
}

func (s *Store) put(ctx context.Context, folderID string, entry model.Entry) error {
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO entries(folder,path,manifest) VALUES(?,?,?) ON CONFLICT(folder,path) DO UPDATE SET manifest=excluded.manifest", folderID, entry.Path, raw)
	return err
}

// A constant-time budget check runs before creating a destination file. SQLite
// triggers enforce the same limits atomically when the index is committed.
func (s *Store) checkCapacity(ctx context.Context, folderID string, e model.Entry) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	var count, size int64
	err = s.db.QueryRowContext(ctx, `SELECT
 COALESCE((SELECT entries FROM folder_usage WHERE folder=?),0)+1-(SELECT count(*) FROM entries WHERE folder=? AND path=?),
 COALESCE((SELECT bytes FROM folder_usage WHERE folder=?),0)+?-COALESCE((SELECT length(manifest)+1 FROM entries WHERE folder=? AND path=?),0)`,
		folderID, folderID, e.Path, folderID, len(raw)+1, folderID, e.Path).Scan(&count, &size)
	if err != nil {
		return err
	}
	if count > MaxEntries || size > MaxManifestBytes-2 {
		return errors.New("folder index exceeds manifest limits")
	}
	return nil
}
