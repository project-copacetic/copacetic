package types

import (
	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

const (
	AnnotationPatchOriginKind   = "sh.copa.patch.origin.kind"
	AnnotationPatchOriginName   = "sh.copa.patch.origin.name"
	AnnotationPatchOriginDigest = "sh.copa.patch.origin.digest"
	PatchOriginImage            = "image-ref"
	PatchOriginOCI              = "oci-layout"
)

// SourceLineage identifies the original non-Copa content selected for a patch.
// Digest is authoritative. OCI origins may omit Name; it must never be a local path.
type SourceLineage struct {
	Kind   string
	Name   string
	Digest digest.Digest
}

// Valid reports whether the origin tuple has a supported kind and consistent identity.
func (lineage *SourceLineage) Valid() bool {
	if lineage == nil || lineage.Digest.Validate() != nil {
		return false
	}
	if lineage.Kind != PatchOriginImage && lineage.Kind != PatchOriginOCI {
		return false
	}
	if lineage.Name == "" {
		return lineage.Kind == PatchOriginOCI
	}
	named, err := reference.ParseNormalizedNamed(lineage.Name)
	if err != nil {
		return false
	}
	if pinned, ok := named.(reference.Digested); ok && pinned.Digest() != lineage.Digest {
		return false
	}
	return true
}

// Annotations returns a complete origin tuple, or nil for an unknown identity.
func (lineage *SourceLineage) Annotations() map[string]string {
	if !lineage.Valid() {
		return nil
	}
	annotations := map[string]string{
		AnnotationPatchOriginKind:   lineage.Kind,
		AnnotationPatchOriginDigest: lineage.Digest.String(),
	}
	if lineage.Name != "" {
		annotations[AnnotationPatchOriginName] = lineage.Name
	}
	return annotations
}

// SourceLineageFromAnnotations reads only Copa-owned origin metadata.
// Application-owned org.opencontainers.image.base.* fields are never control data.
func SourceLineageFromAnnotations(annotations map[string]string) *SourceLineage {
	lineage := &SourceLineage{
		Kind:   annotations[AnnotationPatchOriginKind],
		Name:   annotations[AnnotationPatchOriginName],
		Digest: digest.Digest(annotations[AnnotationPatchOriginDigest]),
	}
	if !lineage.Valid() {
		return nil
	}
	if lineage.Name != "" {
		named, _ := reference.ParseNormalizedNamed(lineage.Name)
		if reference.IsNameOnly(named) {
			named = reference.TagNameOnly(named)
		}
		lineage.Name = named.String()
	}
	return lineage
}

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

// PatchResult represents the result of a single arch patch operation.
type PatchResult struct {
	OriginalRef  reference.Named
	PatchedDesc  *ispec.Descriptor
	PatchedRef   reference.Named
	PatchedState *llb.State                // BuildKit state for OCI export
	ConfigData   []byte                    // Image config data
	Summary      *unversioned.PatchSummary // Patch summary, nil if unavailable
}

type MultiPlatformSummary struct {
	Platform string
	Status   string
	Ref      string
	Message  string
}
