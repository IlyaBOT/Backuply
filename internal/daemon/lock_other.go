//go:build !linux

package daemon

import (
	"errors"
	"os"
)

func LockState(string) (*os.File, error) {
	return nil, errors.New("the stage-one daemon currently supports Linux only")
}
