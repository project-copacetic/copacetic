package vex

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	openvex "github.com/openvex/go-vex/pkg/vex"

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
	if _, err := os.Lstat(file); err == nil {
		return writeBufferedVEXDocumentFile(file, write)
	} else if !os.IsNotExist(err) {
		return err
	}

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

func writeBufferedVEXDocumentFile(file string, write func(io.Writer) error) error {
	var buf bytes.Buffer
	if err := write(&buf); err != nil {
		return err
	}
	return os.WriteFile(file, buf.Bytes(), 0o600)
}

// DocumentInput describes validated updates for one produced image manifest.
type DocumentInput struct {
	Updates     *unversioned.UpdateManifest
	PackageType string
	Image       string
}

// TryOutputVexDocuments emits one document while retaining each platform's
// product identity. Statements never extend to unpatched sibling manifests.
func TryOutputVexDocuments(inputs []DocumentInput, format, file string) error {
	if format != "openvex" {
		return fmt.Errorf("unsupported output format %s specified", format)
	}
	var combined *openvex.VEX
	for _, input := range inputs {
		doc, err := (&OpenVex{}).createVEXDocument(input.Updates, input.Image, input.PackageType)
		if err != nil {
			return err
		}
		if combined == nil {
			combined = doc
		} else {
			combined.Statements = append(combined.Statements, doc.Statements...)
		}
	}
	if combined == nil {
		return nil
	}
	id, err := combined.GenerateCanonicalID()
	if err != nil {
		return err
	}
	combined.ID = id
	return writeVEXDocumentFile(file, combined.ToJSON)
}
