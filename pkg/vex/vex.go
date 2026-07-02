package vex

import (
	"fmt"
	"os"

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
		docFile, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if err := doc.ToJSON(docFile); err != nil {
			_ = docFile.Close()
			return err
		}
		if err := docFile.Close(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported output format %s specified", format)
	}
	return nil
}
