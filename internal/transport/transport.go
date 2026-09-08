// Package transport implements the version-one persistent TCP/TLS block protocol.
// Each connection runs sequential requests; clients can open independent sessions.
package transport

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/IlyaBOT/Backuply/internal/model"
)

const (
	Version          = 1
	maxControl       = 4 << 20
	maxIndexBytes    = 64 << 20
	maxEntries       = 100000
	maxSessions      = 32
	operationTimeout = 30 * time.Second
	idleTimeout      = 60 * time.Second
)

// Backend must authorize peerID for the requested folder before reading any data.
// Implementations must observe context cancellation.
type Backend interface {
	List(context.Context, string, string) ([]model.Entry, error)
	ReadBlock(context.Context, string, string, string, string, model.Block) ([]byte, error)
}

type message struct {
	Type    string       `json:"type"`
	Version int          `json:"version,omitempty"`
	Folder  string       `json:"folder,omitempty"`
	Path    string       `json:"path,omitempty"`
	Hash    string       `json:"hash,omitempty"`
	Block   *model.Block `json:"block,omitempty"`
	Entry   *model.Entry `json:"entry,omitempty"`
	Error   string       `json:"error,omitempty"`
}

type wire struct {
	r *bufio.Reader
	w *bufio.Writer
}

func newWire(conn net.Conn) *wire {
	return &wire{bufio.NewReaderSize(conn, 32<<10), bufio.NewWriterSize(conn, 32<<10)}
}

func readFrame(r io.Reader, limit int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || uint64(n) > uint64(limit) {
		return nil, fmt.Errorf("invalid frame size %d", n)
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(r, b)
	return b, err
}

func writeFrame(w io.Writer, data []byte, limit int) error {
	if len(data) == 0 || len(data) > limit {
		return errors.New("frame size exceeds protocol limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	for _, b := range [][]byte{header[:], data} {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (w *wire) read() (message, int, error) {
	b, err := readFrame(w.r, maxControl)
	if err != nil {
		return message{}, 0, err
	}
	var msg message
	if err := json.Unmarshal(b, &msg); err != nil {
		return message{}, 0, fmt.Errorf("invalid control frame: %w", err)
	}
	return msg, len(b), nil
}

func (w *wire) write(msg message) (int, error) {
	b, err := json.Marshal(msg)
	if err != nil {
		return 0, err
	}
	return len(b), writeFrame(w.w, b, maxControl)
}

func (w *wire) send(msg message) error {
	if _, err := w.write(msg); err != nil {
		return err
	}
	return w.w.Flush()
}

func validateTLS(config *tls.Config, server bool) error {
	if config == nil {
		return errors.New("TLS configuration is required")
	}
	if config.MinVersion < tls.VersionTLS13 {
		return errors.New("TLS 1.3 minimum is required")
	}
	if server {
		verified := config.ClientAuth == tls.RequireAndVerifyClientCert
		pinned := config.ClientAuth == tls.RequireAnyClientCert && config.VerifyConnection != nil
		if !verified && !pinned {
			return errors.New("mutually authenticated TLS is required")
		}
	} else if config.InsecureSkipVerify && config.VerifyConnection == nil {
		return errors.New("TLS peer verification is required")
	}
	return nil
}

// Serve takes ownership of a plain TCP listener and closes it and all sessions on
// cancellation or accept failure. TLS must require verified client certificates.
func Serve(ctx context.Context, listener net.Listener, tlsConfig *tls.Config, backend Backend) error {
	defer listener.Close()
	if err := validateTLS(tlsConfig, true); err != nil {
		return err
	}
	if backend == nil {
		return errors.New("backend is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	var mu sync.Mutex
	active := make(map[net.Conn]struct{})
	var wg sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for conn := range active {
			conn.Close()
		}
	}()
	defer func() { cancel(); <-stopped; wg.Wait() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		mu.Lock()
		if len(active) >= maxSessions || ctx.Err() != nil {
			mu.Unlock()
			conn.Close()
			continue
		}
		active[conn] = struct{}{}
		wg.Add(1)
		mu.Unlock()
		go func() {
			defer wg.Done()
			defer func() { conn.Close(); mu.Lock(); delete(active, conn); mu.Unlock() }()
			serveConn(ctx, conn, tlsConfig, backend)
		}()
	}
}

func serveConn(ctx context.Context, raw net.Conn, config *tls.Config, backend Backend) {
	conn := tls.Server(raw, config)
	if err := conn.SetDeadline(time.Now().Add(operationTimeout)); err != nil {
		return
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return
	}
	fingerprint := sha256.Sum256(certs[0].Raw)
	peerID := hex.EncodeToString(fingerprint[:])
	w := newWire(conn)
	hello, _, err := w.read()
	if err != nil || hello.Type != "hello" || hello.Version != Version {
		return
	}
	if err := w.send(message{Type: "hello", Version: Version}); err != nil {
		return
	}
	for {
		if err := conn.SetDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}
		request, _, err := w.read()
		if err != nil {
			return
		}
		requestCtx, cancel := context.WithTimeout(ctx, operationTimeout)
		if err := conn.SetDeadline(time.Now().Add(operationTimeout)); err != nil {
			cancel()
			return
		}
		err = handleRequest(requestCtx, w, backend, peerID, request)
		cancel()
		if err != nil {
			return
		}
	}
}

func handleRequest(ctx context.Context, w *wire, backend Backend, peerID string, request message) error {
	if request.Folder == "" || len(request.Folder) > 256 || len(request.Path) > 4096 {
		return errors.New("invalid request")
	}
	switch request.Type {
	case "list":
		entries, err := backend.List(ctx, peerID, request.Folder)
		if err != nil {
			return sendError(w, err)
		}
		if len(entries) > maxEntries {
			return sendError(w, errors.New("index entry limit exceeded"))
		}
		total := 0
		for i := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, err := w.write(message{Type: "entry", Entry: &entries[i]})
			if err != nil {
				return err
			}
			total += n
			if total > maxIndexBytes {
				return errors.New("index metadata limit exceeded")
			}
		}
		return w.send(message{Type: "end"})
	case "block":
		if request.Block == nil || request.Block.Size <= 0 || request.Block.Size > model.BlockSize || request.Block.Offset < 0 || len(request.Hash) != 64 || len(request.Block.Hash) != 64 {
			return errors.New("invalid block request")
		}
		data, err := backend.ReadBlock(ctx, peerID, request.Folder, request.Path, request.Hash, *request.Block)
		if err != nil {
			return sendError(w, err)
		}
		if len(data) != request.Block.Size {
			return sendError(w, errors.New("backend returned incorrect block size"))
		}
		if _, err := w.write(message{Type: "block"}); err != nil {
			return err
		}
		if err := writeFrame(w.w, data, model.BlockSize); err != nil {
			return err
		}
		return w.w.Flush()
	default:
		return errors.New("unknown request type")
	}
}

func sendError(w *wire, _ error) error {
	// Filesystem paths and backend internals are kept in the local process.
	return w.send(message{Type: "error", Error: "request rejected"})
}

// Client serializes operations over one authenticated persistent connection.
// Any failed operation closes the session so partial frames cannot be reused.
type Client struct {
	conn net.Conn
	w    *wire
	gate chan struct{}
}

func Dial(ctx context.Context, address string, tlsConfig *tls.Config) (*Client, error) {
	if err := validateTLS(tlsConfig, false); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	dialer := tls.Dialer{Config: tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	c := &Client{conn: conn, w: newWire(conn), gate: make(chan struct{}, 1)}
	err = c.operation(ctx, func() error {
		if err := c.w.send(message{Type: "hello", Version: Version}); err != nil {
			return err
		}
		msg, _, err := c.w.read()
		if err != nil {
			return err
		}
		if msg.Type != "hello" || msg.Version != Version {
			return errors.New("unsupported peer protocol")
		}
		return nil
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) operation(ctx context.Context, fn func() error) error {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.gate }()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err := c.conn.SetDeadline(deadline); err != nil {
		c.Close()
		return err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	err := fn()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		c.Close()
	}
	return err
}

func (c *Client) List(ctx context.Context, folderID string) ([]model.Entry, error) {
	var entries []model.Entry
	err := c.operation(ctx, func() error {
		if err := c.w.send(message{Type: "list", Folder: folderID}); err != nil {
			return err
		}
		total := 0
		for {
			msg, n, err := c.w.read()
			if err != nil {
				return err
			}
			total += n
			if total > maxIndexBytes {
				return errors.New("peer index metadata limit exceeded")
			}
			switch msg.Type {
			case "entry":
				if msg.Entry == nil || len(entries) >= maxEntries {
					return errors.New("invalid peer index")
				}
				entries = append(entries, *msg.Entry)
			case "end":
				return nil
			case "error":
				return errors.New("peer rejected list request")
			default:
				return errors.New("unexpected index response")
			}
		}
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func (c *Client) ReadBlock(ctx context.Context, folderID, path, entryHash string, block model.Block) ([]byte, error) {
	if block.Size <= 0 || block.Size > model.BlockSize || block.Offset < 0 {
		return nil, errors.New("invalid block")
	}
	var data []byte
	err := c.operation(ctx, func() error {
		if err := c.w.send(message{Type: "block", Folder: folderID, Path: path, Hash: entryHash, Block: &block}); err != nil {
			return err
		}
		msg, _, err := c.w.read()
		if err != nil {
			return err
		}
		if msg.Type == "error" {
			return errors.New("peer rejected block request")
		}
		if msg.Type != "block" {
			return errors.New("unexpected block response")
		}
		data, err = readFrame(c.w.r, block.Size)
		if err != nil {
			return err
		}
		if len(data) != block.Size {
			return errors.New("incorrect block length")
		}
		hash := sha256.Sum256(data)
		if hex.EncodeToString(hash[:]) != block.Hash {
			return errors.New("block hash mismatch")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return data, nil
}
