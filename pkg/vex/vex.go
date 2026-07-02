package vex

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

type Vex interface {
	CreateVEXDocument(updates *unversioned.UpdateManifest, patchedImageName string, pkgmgr pkgmgr.PackageManager) (string, error)
}

func TryOutputVexDocument(updates *unversioned.UpdateManifest, pkgType, patchedImageName, format, file string) error {
	switch format {
	case "openvex":
		ov := &OpenVex{}
		doc, err := ov.createVEXDocument(updates, patchedImageName, pkgType)
		if err != nil {
			return err
		}
		return writeVEXDocumentFile(file, doc.ToJSON)
	default:
		return fmt.Errorf("unsupported output format %s specified", format)
	}
}

func writeVEXDocumentFile(file string, write func(io.Writer) error) error {
	dir := filepath.Dir(file)
	tmpFile, err := os.CreateTemp(dir, "."+filepath.Base(file)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.Remove(tmpName)
		}
	}()

	if err := write(tmpFile); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, file); err != nil {
		return err
	}
	succeeded = true
	return nil
}
