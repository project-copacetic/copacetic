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

func TryOutputVexDocument(updates *unversioned.UpdateManifest, pkgmgr pkgmgr.PackageManager, patchedImageName, format, file string) error {
	var doc string
	var err error

	switch format {
	case "openvex":
		ov := &OpenVex{}
		doc, err = ov.CreateVEXDocument(updates, patchedImageName, pkgmgr)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported output format %s specified", format)
	}
	return os.WriteFile(file, []byte(doc), 0o600)
}
