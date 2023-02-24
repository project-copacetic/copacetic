// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package testutils

import (
	"log"
	"os"
	"path/filepath"
)

func CreateTempFileWithContent(dir string, dbType string) {
	path := filepath.Join(dir, dbType)
	file, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	_, err = file.WriteString("test")
	if err != nil {
		log.Fatal(err)
	}
}
