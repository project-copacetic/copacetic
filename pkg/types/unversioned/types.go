package unversioned

type UpdateManifest struct {
	Metadata    Metadata           `json:"metadata"`
	OSUpdates   UpdatePackages     `json:"osupdates"`
	LangUpdates LangUpdatePackages `json:"langupdates"`
}

type UpdatePackages []UpdatePackage

type LangUpdatePackages []UpdatePackage

type Metadata struct {
	OS          OS     `json:"os"`
	Config      Config `json:"config"`
	NodeVersion string `json:"nodeVersion,omitempty"` // Detected Node.js version from image
	YarnVersion string `json:"yarnVersion,omitempty"` // Detected Yarn version from image
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
	Type             string `json:"type"`
	Class            string `json:"class"`
	PkgPath          string `json:"pkgPath,omitempty"` // Path to package from Trivy report (e.g., "var/lib/ghost/versions/6.2.0/node_modules/@babel/runtime/package.json")
}
