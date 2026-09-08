// Package config reads the deliberately small, strict Backuply INI format.
package config

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen       string
	StateDir     string
	ScanInterval time.Duration
	Peers        map[string]Peer
	Folders      map[string]Folder
}

type Peer struct{ Name, Address, DeviceID string }
type Folder struct {
	ID, Path, Source string
	Peers            []string
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var idPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var sectionPattern = regexp.MustCompile(`^(peer|folder) "([A-Za-z0-9][A-Za-z0-9_.-]*)"$`)

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	return Parse(f)
}

func Parse(r io.Reader) (Config, error) {
	c := Config{Listen: "127.0.0.1:24800", ScanInterval: 5 * time.Second, Peers: map[string]Peer{}, Folders: map[string]Folder{}}
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), 1024*1024)
	sections, keys := map[string]bool{}, map[string]bool{}
	kind, name := "", ""
	line := 0
	for s.Scan() {
		line++
		v := strings.TrimSpace(s.Text())
		if v == "" || strings.HasPrefix(v, "#") || strings.HasPrefix(v, ";") {
			continue
		}
		if strings.HasPrefix(v, "[") {
			if !strings.HasSuffix(v, "]") {
				return Config{}, fmt.Errorf("line %d: malformed section", line)
			}
			header := strings.TrimSpace(v[1 : len(v)-1])
			if sections[header] {
				return Config{}, fmt.Errorf("line %d: duplicate section %q", line, header)
			}
			sections[header] = true
			kind, name = "service", ""
			if header != "service" {
				m := sectionPattern.FindStringSubmatch(header)
				if m == nil {
					return Config{}, fmt.Errorf("line %d: unknown or malformed section %q", line, header)
				}
				kind, name = m[1], m[2]
				if kind == "peer" {
					c.Peers[name] = Peer{Name: name}
				} else {
					c.Folders[name] = Folder{ID: name}
				}
			}
			continue
		}
		key, value, ok := strings.Cut(v, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !ok || kind == "" || key == "" {
			return Config{}, fmt.Errorf("line %d: expected key = value inside a section", line)
		}
		qualified := kind + "/" + name + "/" + key
		if keys[qualified] {
			return Config{}, fmt.Errorf("line %d: duplicate key %q", line, key)
		}
		keys[qualified] = true
		if strings.HasPrefix(value, `"`) {
			var err error
			value, err = strconv.Unquote(value)
			if err != nil {
				return Config{}, fmt.Errorf("line %d: invalid quoted value: %w", line, err)
			}
		}
		unknown := false
		switch kind {
		case "service":
			switch key {
			case "listen":
				c.Listen = value
			case "state_dir":
				c.StateDir = value
			case "scan_interval":
				var err error
				c.ScanInterval, err = time.ParseDuration(value)
				if err != nil {
					return Config{}, fmt.Errorf("line %d: scan_interval: %w", line, err)
				}
			default:
				unknown = true
			}
		case "peer":
			p := c.Peers[name]
			switch key {
			case "address":
				p.Address = value
			case "device_id":
				p.DeviceID = value
			default:
				unknown = true
			}
			c.Peers[name] = p
		case "folder":
			f := c.Folders[name]
			switch key {
			case "path":
				f.Path = value
			case "source":
				f.Source = value
			case "peers":
				if value != "" {
					for _, p := range strings.Split(value, ",") {
						f.Peers = append(f.Peers, strings.TrimSpace(p))
					}
				}
			default:
				unknown = true
			}
			c.Folders[name] = f
		}
		if unknown {
			return Config{}, fmt.Errorf("line %d: unknown %s key %q", line, kind, key)
		}
	}
	if err := s.Err(); err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

func validAddress(address string, allowZero bool) bool {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	p, err := strconv.Atoi(port)
	return err == nil && (p > 0 || (allowZero && p == 0)) && p <= 65535
}

func (c Config) Validate() error {
	if !validAddress(c.Listen, true) {
		return fmt.Errorf("listen must be host:port with port 0..65535 (0 selects an ephemeral port)")
	}
	if len(c.Peers) > 32 || len(c.Folders) > 128 {
		return fmt.Errorf("configuration is limited to 32 peers and 128 folders")
	}
	if c.ScanInterval < 100*time.Millisecond {
		return fmt.Errorf("scan_interval must be at least 100ms")
	}
	paths := map[string]string{"state_dir": c.StateDir}
	ids := map[string]string{}
	for name, p := range c.Peers {
		if !namePattern.MatchString(name) || name == "local" || p.Name != name {
			return fmt.Errorf("invalid peer name %q (local is reserved)", name)
		}
		if !validAddress(p.Address, false) {
			return fmt.Errorf("peer %q: invalid address", name)
		}
		if !idPattern.MatchString(p.DeviceID) {
			return fmt.Errorf("peer %q: device_id must contain 64 lowercase hexadecimal characters", name)
		}
		if previous, ok := ids[p.DeviceID]; ok {
			return fmt.Errorf("peers %q and %q have the same device_id", previous, name)
		}
		ids[p.DeviceID] = name
	}
	for id, f := range c.Folders {
		if !namePattern.MatchString(id) || f.ID != id {
			return fmt.Errorf("invalid folder id %q", id)
		}
		paths["folder "+id] = f.Path
		peers := map[string]bool{}
		for _, peer := range f.Peers {
			if _, ok := c.Peers[peer]; !ok {
				return fmt.Errorf("folder %q: unknown peer %q", id, peer)
			}
			if peers[peer] {
				return fmt.Errorf("folder %q: duplicate peer %q", id, peer)
			}
			peers[peer] = true
		}
		if f.Source != "local" && !peers[f.Source] {
			return fmt.Errorf("folder %q: source must be local or a listed peer", id)
		}
	}
	resolved := map[string]string{}
	for name, path := range paths {
		if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
			return fmt.Errorf("%s: path must be absolute", name)
		}
		canonical, err := canonicalPath(filepath.Clean(path))
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		for other, previous := range resolved {
			if containsPath(canonical, previous) || containsPath(previous, canonical) {
				return fmt.Errorf("%s and %s paths overlap", name, other)
			}
		}
		resolved[name] = canonical
	}
	return nil
}

func containsPath(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Resolve the existing prefix too: a symlink must not conceal overlapping roots.
func canonicalPath(path string) (string, error) {
	if _, err := os.Lstat(path); err == nil {
		return filepath.EvalSymlinks(path)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path, nil
	}
	resolved, err := canonicalPath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}
