package types

import (
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerabilityID"`
}

type UpdatePackages []UpdatePackage

type UpdateManifest struct {
	OSType    string         `json:"osType"`
	OSVersion string         `json:"osVersion"`
	Arch      string         `json:"arch"`
	Updates   UpdatePackages `json:"updates"`
}

// PatchPlatform is an extension of ispec.Platform but with a reportFile.
type PatchPlatform struct {
	ispec.Platform
	ReportFile string `json:"reportFile"`
}

// PatchResult represents the result of a single arch patch operation.
type PatchResult struct {
	OriginalImage string
	PatchedImage  string
	Digest        string
}
