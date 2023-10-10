package v1alpha1

const APIVersion string = "v1alpha1"

type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerability"`
}

type UpdatePackages []UpdatePackage

type UpdateManifest struct {
	APIVersion string         `json:"apiVersion"`
	OSType     string         `json:"ostype"`
	OSVersion  string         `json:"osversion"`
	Arch       string         `json:"arch"`
	Updates    UpdatePackages `json:"updates"`
}
