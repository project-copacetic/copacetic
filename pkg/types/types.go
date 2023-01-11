// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package types

type UpdatePackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type UpdatePackages []UpdatePackage

type UpdateManifest struct {
	OSType    string         `json:"ostype"`
	OSVersion string         `json:"osversion"`
	Arch      string         `json:"arch"`
	Updates   UpdatePackages `json:"updates"`
}
