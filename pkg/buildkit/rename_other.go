//go:build !linux && !darwin

package buildkit

import "errors"

func renameDirectoryNoReplace(_, _ string) error {
	return errors.ErrUnsupported
}
