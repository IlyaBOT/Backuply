package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// LockState prevents two processes from changing one identity/index concurrently.
// Closing the returned file releases the advisory lock, including after a crash.
func LockState(stateDir string) (*os.File, error) {
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "daemon.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("state directory is already in use: %w", err)
	}
	return f, nil
}
