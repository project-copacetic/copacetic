package patch

import (
	"encoding/json"
	"fmt"

	"github.com/containerd/platforms"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
)

const (
	ARM64 = "arm64"
)

var validPlatforms = []string{
	"linux/386",
	"linux/amd64",
	"linux/arm",
	"linux/arm/v5",
	"linux/arm/v6",
	"linux/arm/v7",
	"linux/arm64",
	"linux/arm64/v8",
	"linux/ppc64le",
	"linux/s390x",
	"linux/riscv64",
}

// archTag returns "patched-arm64" or "patched-arm-v7" etc.
func archTag(base, arch, variant string) string {
	if variant != "" {
		return fmt.Sprintf("%s-%s-%s", base, arch, variant)
	}
	return fmt.Sprintf("%s-%s", base, arch)
}

// normalizeConfigForPlatform adjusts the image configuration for a specific platform.
func normalizeConfigForPlatform(j []byte, p *types.PatchPlatform) ([]byte, error) {
	if p == nil {
		return j, fmt.Errorf("platform is nil")
	}

	var m map[string]any
	if err := json.Unmarshal(j, &m); err != nil {
		return nil, err
	}

	m["architecture"] = p.Architecture
	if p.Variant != "" {
		m["variant"] = p.Variant
	} else {
		delete(m, "variant")
	}
	m["os"] = p.OS

	return json.Marshal(m)
}

// filterPlatforms filters discovered platforms based on user-specified target platforms.
func filterPlatforms(discoveredPlatforms []types.PatchPlatform, targetPlatforms []string) []types.PatchPlatform {
	var filtered []types.PatchPlatform

	for _, target := range targetPlatforms {
		// Validate platform against allowed list
		if !slices.Contains(validPlatforms, target) {
			log.Warnf("Platform %s is not in the list of valid platforms: %v", target, validPlatforms)
			continue
		}

		targetPlatform, err := platforms.Parse(target)
		if err != nil {
			log.Warnf("Invalid platform format %s: %v", target, err)
			continue
		}
		targetPlatform = platforms.Normalize(targetPlatform)

		for _, discovered := range discoveredPlatforms {
			if platforms.Only(targetPlatform).Match(discovered.Platform) {
				filtered = append(filtered, discovered)
				break
			}
		}
	}

	return filtered
}

// getPlatformDescriptorFromManifest gets the descriptor for a specific platform from a multi-arch manifest.
func getPlatformDescriptorFromManifest(
	imageRef string,
	targetPlatform *types.PatchPlatform,
) (*ispec.Descriptor, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("error parsing reference %q: %w", imageRef, err)
	}

	// Try local daemon first, then fall back to remote
	desc, err := buildkit.TryGetManifestFromLocal(ref)
	if err != nil {
		log.Debugf("Failed to get descriptor from local daemon: %v, trying remote registry", err)
		desc, err = remote.Get(ref)
		if err != nil {
			return nil, fmt.Errorf("error fetching descriptor for %q from both local daemon and remote registry: %w", imageRef, err)
		}
		log.Debugf("Successfully fetched descriptor from remote registry for %s", imageRef)
	} else {
		log.Debugf("Successfully fetched descriptor from local daemon for %s", imageRef)
	}

	if !desc.MediaType.IsIndex() {
		return nil, fmt.Errorf("expected multi-platform image but got single-platform image")
	}

	index, err := desc.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("error getting image index: %w", err)
	}

	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("error getting manifest: %w", err)
	}

	// Find the descriptor for the target platform
	for i := range manifest.Manifests {
		m := &manifest.Manifests[i]
		if m.Platform == nil {
			continue
		}

		// Normalize the variant comparison - treat missing variant as empty string
		manifestVariant := m.Platform.Variant
		targetVariant := targetPlatform.Variant
		if m.Platform.Architecture == ARM64 && manifestVariant == "v8" {
			manifestVariant = ""
		}
		if targetPlatform.Architecture == ARM64 && targetVariant == "v8" {
			targetVariant = ""
		}

		if m.Platform.OS == targetPlatform.OS &&
			m.Platform.Architecture == targetPlatform.Architecture &&
			manifestVariant == targetVariant &&
			m.Platform.OSVersion == targetPlatform.OSVersion {
			// Convert the descriptor to the expected format
			ociDesc := &ispec.Descriptor{
				MediaType: string(m.MediaType),
				Size:      m.Size,
				Digest:    digest.Digest(m.Digest.String()),
				Platform: &ispec.Platform{
					OS:           m.Platform.OS,
					Architecture: m.Platform.Architecture,
					Variant:      m.Platform.Variant,
					OSVersion:    m.Platform.OSVersion,
					OSFeatures:   m.Platform.OSFeatures,
				},
				Annotations: m.Annotations,
			}
			return ociDesc, nil
		}
	}

	return nil, fmt.Errorf("platform %s/%s not found in manifest", targetPlatform.OS, targetPlatform.Architecture)
}
