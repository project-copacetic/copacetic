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
