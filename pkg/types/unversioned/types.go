package unversioned

type UpdateManifest struct {
	Metadata    Metadata       `json:"metadata"`
	Updates     UpdatePackages `json:"updates"`
	NodeUpdates UpdatePackages `json:"nodeUpdates,omitempty"`
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
	Arch    string `json:"arch"`
	Variant string `json:"variant"`
}

type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerabilityID"`
}
