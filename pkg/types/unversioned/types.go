package unversioned

type UpdateManifest struct {
	Metadata    Metadata           `json:"metadata"`
	OSUpdates   UpdatePackages     `json:"osupdates"`
	LangUpdates LangUpdatePackages `json:"langupdates"`
}

type UpdatePackages []UpdatePackage

type LangUpdatePackages []UpdatePackage

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
	Type             string `json:"type"`
	Class            string `json:"class"`
}
