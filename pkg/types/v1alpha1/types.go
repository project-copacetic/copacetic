package v1alpha1

const APIVersion string = "v1alpha1"

type UpdateManifest struct {
	APIVersion string         `json:"apiVersion"`
	Metadata   Metadata       `json:"metadata"`
	Updates    UpdatePackages `json:"updates"`
}

type UpdatePackages []UpdatePackage

type Metadata struct {
	OS     OS     `json:"os"`
	Config Config `json:"config"`
}

type OS struct {
	Type    string `json:"type"`
	Version string `json:"version"`
}

type Config struct {
	Arch string `json:"arch"`
}

type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerabilityID"`
}
