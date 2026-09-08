package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	return fmt.Sprintf(`[service]
state_dir = %s/state
listen = 0.0.0.0:24800
scan_interval = 2s
[peer "laptop"]
address = [::1]:24800
device_id = %s
[folder "projects"]
path = "%s/projects"
source = laptop
peers = laptop
`, base, strings.Repeat("a", 64), base)
}

func TestParse(t *testing.T) {
	c, err := Parse(strings.NewReader("# comment\n; comment\n" + fixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if c.ScanInterval != 2*time.Second || c.Folders["projects"].Source != "laptop" || c.Peers["laptop"].Address != "[::1]:24800" {
		t.Fatalf("wrong config: %+v", c)
	}
}

func TestRejectInvalidConfig(t *testing.T) {
	base := fixture(t)
	cases := map[string]string{
		"unknown key":       base + "typo = yes\n",
		"duplicate key":     base + "source = local\n",
		"duplicate section": base + "[service]\n",
		"unknown section":   base + "[ftp]\n",
		"missing source":    strings.Replace(base, "source = laptop\n", "", 1),
		"source not shared": strings.Replace(base, "peers = laptop", "peers =", 1),
		"unknown peer":      strings.Replace(base, "peers = laptop", "peers = absent", 1),
		"duplicate peer":    strings.Replace(base, "peers = laptop", "peers = laptop,laptop", 1),
		"bad fingerprint":   strings.Replace(base, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"relative path":     strings.Replace(base, "state_dir = /", "state_dir = ", 1),
		"fast interval":     strings.Replace(base, "2s", "1ms", 1),
		"bad port":          strings.Replace(base, "0.0.0.0:24800", "0.0.0.0:65536", 1),
		"broken quote":      base + "path = \"broken\n",
		"outside section":   "state_dir = /tmp/state\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(input)); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}

func TestRejectOverlappingPaths(t *testing.T) {
	base := t.TempDir()
	for _, folder := range []string{base, filepath.Join(base, "state"), filepath.Join(base, "state", "child")} {
		input := fmt.Sprintf("[service]\nstate_dir=%s/state\n[folder \"a\"]\npath=%s\nsource=local\n", base, folder)
		if _, err := Parse(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted overlap %s", folder)
		}
	}
	if err := os.Mkdir(filepath.Join(base, "state"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "state"), filepath.Join(base, "alias")); err != nil {
		t.Fatal(err)
	}
	input := fmt.Sprintf("[service]\nstate_dir=%s/state\n[folder \"a\"]\npath=%s/alias/child\nsource=local\n", base, base)
	if _, err := Parse(strings.NewReader(input)); err == nil {
		t.Fatal("accepted symlink-hidden overlap")
	}
}

func TestEmptyFoldersAndLocalSource(t *testing.T) {
	input := fmt.Sprintf("[service]\nstate_dir=%s/state\n", t.TempDir())
	if _, err := Parse(strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	input += fmt.Sprintf("[folder \"projects\"]\npath=%s/projects\nsource=local\n", t.TempDir())
	if _, err := Parse(strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
}

func TestEphemeralListenerAndResourceLimits(t *testing.T) {
	c, err := Parse(strings.NewReader(strings.Replace(fixture(t), "0.0.0.0:24800", "127.0.0.1:0", 1)))
	if err != nil {
		t.Fatal(err)
	}
	p := c.Peers["laptop"]
	p.Address = "127.0.0.1:0"
	c.Peers["laptop"] = p
	if err := c.Validate(); err == nil {
		t.Fatal("accepted ephemeral peer destination")
	}
	for _, count := range []int{33, 129} {
		c := Config{Listen: "127.0.0.1:0", StateDir: "/state", ScanInterval: time.Second, Peers: map[string]Peer{}, Folders: map[string]Folder{}}
		for i := 0; i < count; i++ {
			name := fmt.Sprintf("item%d", i)
			if count == 33 {
				c.Peers[name] = Peer{Name: name, Address: "127.0.0.1:24800", DeviceID: fmt.Sprintf("%064x", i)}
			} else {
				c.Folders[name] = Folder{ID: name, Path: "/folders/" + name, Source: "local"}
			}
		}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "limited") {
			t.Fatalf("expected resource limit, got %v", err)
		}
	}
}
