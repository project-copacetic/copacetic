// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package utils

import (
	"io/fs"
	"os"
	"path/filepath"
)

func EnsurePath(path string, perm fs.FileMode) (bool, error) {
	createdPath := false
	st, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(path, perm)
		createdPath = (err == nil)
	} else {
		if !st.IsDir() {
			return false, fs.ErrExist
		}
		if st.Mode().Perm() != perm {
			return false, fs.ErrPermission
		}
	}
	return createdPath, err
}

func IsNonEmptyFile(dir, file string) bool {
	p := filepath.Join(dir, file)
	info, err := os.Stat(p)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir() && info.Size() > 0
}
