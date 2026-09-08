// Package daemon coordinates the stage-one single-writer folder replicas.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/IlyaBOT/Backuply/internal/config"
	"github.com/IlyaBOT/Backuply/internal/identity"
	"github.com/IlyaBOT/Backuply/internal/model"
	"github.com/IlyaBOT/Backuply/internal/store"
	"github.com/IlyaBOT/Backuply/internal/transport"
)

type FolderStatus struct {
	Source string `json:"source"`
	Entries int `json:"entries"`
	LastSuccess time.Time `json:"last_success"`
	LastError string `json:"last_error,omitempty"`
	BytesReceived int64 `json:"bytes_received"`
	BytesReused int64 `json:"bytes_reused"`
}

type Status struct {
	Running bool `json:"running"`
	DeviceID string `json:"device_id"`
	Listen string `json:"listen"`
	Stage string `json:"stage"`
	Folders map[string]FolderStatus `json:"folders"`
}

type Daemon struct {
	cfg config.Config
	id *identity.Identity
	store *store.Store
	lock *os.File
	log *slog.Logger
	mu sync.RWMutex
	status Status
}

func New(cfg config.Config, logger *slog.Logger) (*Daemon, error) {
	if err := cfg.Validate(); err != nil { return nil, err }
	lock, err := LockState(cfg.StateDir)
	if err != nil { return nil, err }
	id, err := identity.Load(cfg.StateDir)
	if err != nil { lock.Close(); return nil, fmt.Errorf("load identity (run backuply init first): %w", err) }
	st, err := store.Open(cfg.StateDir)
	if err != nil { lock.Close(); return nil, err }
	if logger == nil { logger = slog.Default() }
	d := &Daemon{cfg:cfg, id:id, store:st, lock:lock, log:logger,
		status:Status{DeviceID:id.ID, Stage:"single-writer-v1", Folders:make(map[string]FolderStatus)}}
	for id, f := range cfg.Folders { d.status.Folders[id] = FolderStatus{Source:f.Source} }
	return d, nil
}

// Close must be called only after Run has returned.
func (d *Daemon) Close() error { return errors.Join(d.store.Close(), d.lock.Close()) }

func (d *Daemon) Status() Status {
	d.mu.RLock(); defer d.mu.RUnlock()
	s := d.status
	s.Folders = make(map[string]FolderStatus, len(d.status.Folders))
	for id, f := range d.status.Folders { s.Folders[id] = f }
	return s
}

func (d *Daemon) update(id string, count int, stats model.Stats, err error) {
	d.mu.Lock()
	s := d.status.Folders[id]
	previousError := s.LastError
	if err != nil { s.LastError = err.Error() } else {
		s.LastError = ""; s.LastSuccess = time.Now().UTC(); s.Entries = count
		s.BytesReceived += stats.BytesReceived; s.BytesReused += stats.BytesReused
	}
	d.status.Folders[id] = s
	d.mu.Unlock()
	if err != nil && previousError != err.Error() { d.log.Warn("folder paused; will retry", "folder", id, "error", err) }
	if err == nil && previousError != "" { d.log.Info("folder recovered", "folder", id) }
	if err == nil && stats.Files > 0 { d.log.Info("folder synchronized", "folder", id, "files", stats.Files, "received", stats.BytesReceived, "reused", stats.BytesReused) }
}

func (d *Daemon) scan(ctx context.Context) {
	for _, id := range sortedFolders(d.cfg.Folders) {
		f := d.cfg.Folders[id]
		if f.Source != "local" { continue }
		entries, err := d.store.Scan(ctx, id, f.Path)
		d.update(id, len(entries), model.Stats{}, err)
		if ctx.Err() != nil { return }
	}
}

func sortedFolders(folders map[string]config.Folder) []string {
	ids := make([]string, 0, len(folders))
	for id := range folders { ids = append(ids, id) }
	sort.Strings(ids)
	return ids
}

// Run blocks until shutdown. A service manager owns backgrounding and restarts.
func (d *Daemon) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.scan(ctx)
	if ctx.Err() != nil { return nil }
	listener, err := net.Listen("tcp", d.cfg.Listen)
	if err != nil { return err }
	defer listener.Close()
	socketPath := filepath.Join(d.cfg.StateDir, "control.sock")
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 { return fmt.Errorf("control path is not a socket: %s", socketPath) }
		if err := os.Remove(socketPath); err != nil { return err }
	} else if !errors.Is(err, os.ErrNotExist) { return err }
	admin, err := net.Listen("unix", socketPath)
	if err != nil { return err }
	defer admin.Close()
	if err := os.Chmod(socketPath, 0600); err != nil { return err }
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d.Status())
	})
	adminServer := &http.Server{Handler:mux, ReadHeaderTimeout:3*time.Second, ReadTimeout:5*time.Second, WriteTimeout:5*time.Second, IdleTimeout:10*time.Second}
	defer adminServer.Close()
	d.mu.Lock(); d.status.Running = true; d.status.Listen = listener.Addr().String(); d.mu.Unlock()
	defer func(){ d.mu.Lock(); d.status.Running = false; d.mu.Unlock() }()
	allowed := make([]string, 0, len(d.cfg.Peers))
	for _, p := range d.cfg.Peers { allowed = append(allowed, p.DeviceID) }
	results := make(chan error, 2)
	go func(){ results <- transport.Serve(ctx, listener, d.id.ServerTLS(allowed), d) }()
	go func(){ results <- adminServer.Serve(admin) }()
	var workers sync.WaitGroup
	workers.Go(func(){
		ticker := time.NewTicker(d.cfg.ScanInterval); defer ticker.Stop()
		for { select { case <-ctx.Done(): return; case <-ticker.C: d.scan(ctx) } }
	})
	for name, p := range d.cfg.Peers {
		folders := make([]config.Folder, 0)
		for _, id := range sortedFolders(d.cfg.Folders) { if f:=d.cfg.Folders[id]; f.Source == name { folders=append(folders,f) } }
		if len(folders) == 0 { continue }
		workers.Go(func(){ d.replicate(ctx, p, folders) })
	}
	d.log.Info("backuply started", "device_id", d.id.ID, "listen", listener.Addr(), "stage", "single-writer-v1")
	var runErr error
	serverReturned := false
	select { case <-ctx.Done(): case runErr = <-results: serverReturned = true }
	cancel()
	_ = listener.Close()
	_ = adminServer.Close()
	workers.Wait()
	// Both servers must have stopped before the caller closes SQLite.
	if !serverReturned { <-results }
	<-results
	if errors.Is(runErr, net.ErrClosed) || errors.Is(runErr, http.ErrServerClosed) { return nil }
	return runErr
}

func (d *Daemon) replicate(ctx context.Context, peer config.Peer, folders []config.Folder) {
	var client *transport.Client
	defer func(){ if client != nil { _ = client.Close() } }()
	ticker := time.NewTicker(d.cfg.ScanInterval); defer ticker.Stop()
	for {
		if ctx.Err() != nil { return }
		for _, folder := range folders {
			if err := store.CheckFolder(folder.Path, folder.ID); err != nil { d.update(folder.ID, 0, model.Stats{}, err); continue }
			if client == nil {
				var err error
				client, err = transport.Dial(ctx, peer.Address, d.id.ClientTLS(peer.DeviceID))
				if err != nil { d.update(folder.ID, 0, model.Stats{}, err); continue }
			}
			entries, err := client.List(ctx, folder.ID)
			var total model.Stats
			if err == nil {
				// Parents precede children. Paths from the peer remain untrusted:
				// Store.Apply performs confinement and manifest validation.
				sort.Slice(entries,func(i,j int)bool{return entries[i].Path < entries[j].Path})
				for _, entry := range entries {
					var stats model.Stats
					stats, err = d.store.Apply(ctx, folder.ID, folder.Path, entry, func(ctx context.Context, block model.Block)([]byte,error){
						return client.ReadBlock(ctx, folder.ID, entry.Path, entry.Hash, block)
					})
					if err != nil { break }
					total.Files += stats.Files; total.BytesReceived += stats.BytesReceived; total.BytesReused += stats.BytesReused
				}
			}
			d.update(folder.ID, len(entries), total, err)
			if err != nil { _ = client.Close(); client = nil }
		}
		select { case <-ctx.Done(): return; case <-ticker.C: }
	}
}

func (d *Daemon) authorize(peerID, folderID string) (config.Folder,error) {
	f, ok := d.cfg.Folders[folderID]
	if !ok { return config.Folder{}, errors.New("folder access denied") }
	allowed := false
	for _, name := range f.Peers { if d.cfg.Peers[name].DeviceID == peerID { allowed = true; break } }
	if !allowed { return config.Folder{}, errors.New("folder access denied") }
	if err := store.CheckFolder(f.Path, f.ID); err != nil { return config.Folder{}, err }
	if f.Source == "local" {
		d.mu.RLock(); status := d.status.Folders[folderID]; d.mu.RUnlock()
		if status.LastSuccess.IsZero() || status.LastError != "" { return config.Folder{}, errors.New("source scan is not available") }
	}
	return f, nil
}

func (d *Daemon) List(ctx context.Context, peerID, folderID string) ([]model.Entry,error) {
	if _, err := d.authorize(peerID, folderID); err != nil { return nil, err }
	return d.store.List(ctx,folderID)
}

func (d *Daemon) ReadBlock(ctx context.Context, peerID, folderID, path, entryHash string, block model.Block)([]byte,error) {
	f, err := d.authorize(peerID,folderID)
	if err != nil { return nil, err }
	return d.store.ReadBlock(ctx,folderID,f.Path,path,entryHash,block)
}

func QueryStatus(ctx context.Context, stateDir string) (Status,error) {
	tr := &http.Transport{DialContext:func(ctx context.Context, _, _ string)(net.Conn,error){
		return (&net.Dialer{}).DialContext(ctx,"unix",filepath.Join(stateDir,"control.sock"))
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport:tr, Timeout:5*time.Second}
	req, err := http.NewRequestWithContext(ctx,"GET","http://localhost/status",nil)
	if err != nil { return Status{},err }
	resp, err := client.Do(req)
	if err != nil { return Status{},fmt.Errorf("daemon unavailable: %w",err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return Status{},fmt.Errorf("daemon status: %s",resp.Status) }
	var status Status
	err = json.NewDecoder(http.MaxBytesReader(nil,resp.Body,1024*1024)).Decode(&status)
	return status,err
}
