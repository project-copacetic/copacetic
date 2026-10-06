package vex

import (
	"bytes"
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

// ImageUpdates is one patched image included in a VEX document.
// Updates is the validated manifest for that image, PkgType selects the
// subcomponent PURLs, and PatchedImageName is placed in the product identifier.
type ImageUpdates struct {
	Updates          *unversioned.UpdateManifest
	PkgType          string
	PatchedImageName string
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

// TryOutputMultiVexDocument writes one OpenVEX document covering every image.
// A vulnerability fixed on more than one image is a single statement whose
// products lists one product per image, in the order of images.
func TryOutputMultiVexDocument(images []ImageUpdates, format, file string) error {
	switch format {
	case "openvex":
		ov := &OpenVex{}
		doc, err := ov.createMultiVEXDocument(images)
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
