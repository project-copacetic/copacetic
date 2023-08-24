// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package types

type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerability"`
}

type UpdatePackages []UpdatePackage

type UpdateManifest struct {
	OSType    string         `json:"ostype"`
	OSVersion string         `json:"osversion"`
	Arch      string         `json:"arch"`
	Updates   UpdatePackages `json:"updates"`
}
