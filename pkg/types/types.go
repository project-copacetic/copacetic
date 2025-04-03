package types

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

// Platform represents a specific platform (OS/architecture combination)
type Platform struct {
	OS         string
	Arch       string
	Variant    string
	Digest     string
	ReportPath string // Path to the vulnerability report for this platform
}

type PatchResult struct {
	OriginalImage string
	PatchedImage  string
	Digest        string
}
