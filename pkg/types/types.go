package types

import (
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

type UpdatePackage struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installedVersion"`
	FixedVersion     string `json:"fixedVersion"`
	VulnerabilityID  string `json:"vulnerabilityID"`
	Type             string `json:"type"`
	Class            string `json:"class"`
}

type UpdatePackages []UpdatePackage

type LangUpdatePackages []UpdatePackage

type UpdateManifest struct {
	OSType      string             `json:"osType"`
	OSVersion   string             `json:"osVersion"`
	Arch        string             `json:"arch"`
	Updates     UpdatePackages     `json:"updates"`
	LangUpdates LangUpdatePackages `json:"langupdates"`
}

// PatchPlatform is an extension of ispec.Platform but with a reportFile.
type PatchPlatform struct {
	ispec.Platform
	ReportFile     string `json:"reportFile"`
	ShouldPreserve bool   `json:"shouldPreserve"`
}

// String returns a string representation of the PatchPlatform.
func (p PatchPlatform) String() string {
	if p.Variant == "" {
		return p.OS + "/" + p.Architecture
	}
	return p.OS + "/" + p.Architecture + "/" + p.Variant
}

// PlatformVEX is the validated update manifest for one patched platform image.
// It is set when a report was provided, the patched digest is known, and the
// validated manifest contains at least one OS or language update.
type PlatformVEX struct {
	// Updates is the validated manifest after errored packages are excluded.
	Updates *unversioned.UpdateManifest
	// PkgType is the package manager type used to build subcomponent PURLs.
	PkgType string
	// NameDigestOrTag is the patched image name with digest.
	NameDigestOrTag string
}

// PatchResult represents the result of a single arch patch operation.
type PatchResult struct {
	OriginalRef  reference.Named
	PatchedDesc  *ispec.Descriptor
	PatchedRef   reference.Named
	PatchedState *llb.State                // BuildKit state for OCI export
	ConfigData   []byte                    // Image config data
	Summary      *unversioned.PatchSummary // Patch summary, nil if unavailable
	// VEX is set when this platform was patched and qualifies for a VEX statement.
	// Nil for preserved, up-to-date, and failed platforms.
	VEX *PlatformVEX
}

type MultiPlatformSummary struct {
	Platform string
	Status   string
	Ref      string
	Message  string
}
