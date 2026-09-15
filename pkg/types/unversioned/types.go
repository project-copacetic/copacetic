package unversioned

// PatchSummary captures counts of vulnerabilities by patch outcome.
type PatchSummary struct {
	Total   int `json:"total"`   // vulns considered (after pkg-type filtering)
	Patched int `json:"patched"` // vulns with a fix that Copa can apply
	Skipped int `json:"skipped"` // vulns with no fix or fix excluded by patch-level
}

type UpdateManifest struct {
	Metadata       Metadata           `json:"metadata"`
	OSUpdates      UpdatePackages     `json:"osupdates"`
	LangUpdates    LangUpdatePackages `json:"langupdates"`
	OSSummary      *PatchSummary      `json:"-"` // internal, not serialized
	LibrarySummary *PatchSummary      `json:"-"` // internal, not serialized
}

// CombinedSummary merges OS and library summaries into a single PatchSummary.
// Returns nil if neither summary is available.
func (m *UpdateManifest) CombinedSummary() *PatchSummary {
	if m.OSSummary == nil && m.LibrarySummary == nil {
		return nil
	}
	s := &PatchSummary{}
	if m.OSSummary != nil {
		s.Total += m.OSSummary.Total
		s.Patched += m.OSSummary.Patched
		s.Skipped += m.OSSummary.Skipped
	}
	if m.LibrarySummary != nil {
		s.Total += m.LibrarySummary.Total
		s.Patched += m.LibrarySummary.Patched
		s.Skipped += m.LibrarySummary.Skipped
	}
	return s
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
