package v1alpha1

const APIVersion = "v1alpha1"

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
