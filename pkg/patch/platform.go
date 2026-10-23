package patch

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/containerd/platforms"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

const (
	ARM64 = "arm64"
)

// For testing: allow stubbing descriptor lookups.
var (
	localPlatformDescriptor = utils.LocalPlatformDescriptor
	getVerifiedRemoteIndex  = buildkit.GetVerifiedRemoteIndexWithContext
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

func isSupportedPatchPlatform(candidate *ispec.Platform) bool {
	if candidate == nil {
		return false
	}
	normalizedCandidate := platforms.Normalize(*candidate)
	for _, supported := range validPlatforms {
		parsed, err := platforms.Parse(supported)
		if err != nil {
			continue
		}
		parsed = platforms.Normalize(parsed)
		if normalizedCandidate.OS == parsed.OS &&
			normalizedCandidate.Architecture == parsed.Architecture &&
			normalizedCandidate.Variant == parsed.Variant {
			return true
		}
	}
	return false
}

// ArchTagSuffixes returns the set of architecture suffixes that Copa appends to base
// tags when pushing per-architecture images (e.g. "386", "amd64", "arm-v7").
// The list is derived from validPlatforms so it stays in sync automatically.
func ArchTagSuffixes() []string {
	suffixes := make([]string, 0, len(validPlatforms))
	for _, p := range validPlatforms {
		spec, err := platforms.Parse(p)
		if err != nil {
			continue
		}
		suffix := spec.Architecture
		if spec.Variant != "" {
			suffix += "-" + spec.Variant
		}
		suffixes = append(suffixes, suffix)
	}
	return suffixes
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
			// Use exact matching instead of platforms.Match to avoid cross-architecture matching
			// This will prevent matching amd64 with 386 even though they're both x86 family
			if targetPlatform.OS == discovered.OS &&
				targetPlatform.Architecture == discovered.Architecture &&
				targetPlatform.Variant == discovered.Variant {
				filtered = append(filtered, discovered)
				break
			}
		}
	}

	return filtered
}

// getPlatformDescriptorFromManifest gets the descriptor for a specific platform
// from an index or a single image manifest.
func getPlatformDescriptorFromManifest(
	ctx context.Context,
	imageRef string,
	targetPlatform *types.PatchPlatform,
) (*ispec.Descriptor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("error parsing reference %q: %w", imageRef, err)
	}

	var desc *remote.Descriptor

	// Prefer the local image store: when the daemon exposes per-platform manifest
	// entries (multi-platform image store), we can return the matching platform's
	// descriptor directly without contacting any registry. This is the critical
	// path for air-gapped patching of images loaded into the daemon (e.g. via
	// `docker load`) without ever being pushed to a registry.
	if localDesc, ok, lerr := localPlatformDescriptor(
		ctx,
		imageRef,
		&ispec.Platform{
			OS:           targetPlatform.OS,
			Architecture: targetPlatform.Architecture,
			Variant:      targetPlatform.Variant,
			OSVersion:    targetPlatform.OSVersion,
			OSFeatures:   targetPlatform.OSFeatures,
		},
	); ok {
		if localDesc != nil {
			log.Debugf("Resolved platform %s/%s descriptor for %s from local daemon", targetPlatform.OS, targetPlatform.Architecture, imageRef)
			return localDesc, nil
		}

		// A legacy daemon may cache only one child of a remote index. Discovery
		// reconciles that shape only for immutable digest references whose remote
		// descriptor matches the requested digest. Apply the same policy here so
		// preserved-platform resolution cannot disagree with discovery. Mutable
		// local tags remain authoritative and never trigger a remote lookup.
		if digestRef, immutable := ref.(name.Digest); immutable {
			desc, err = getVerifiedRemoteIndex(ctx, digestRef)
			if err != nil {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				log.Debugf("Could not verify matching remote index for locally cached %s: %v", imageRef, err)
				desc = nil
			} else {
				log.Debugf("Resolved platform index for locally cached immutable image %s from verified remote descriptor", imageRef)
			}
		}

		if desc == nil {
			// Image is present locally but no per-platform descriptor was returned.
			// Either (a) the requested platform is not part of this image, or
			// (b) the daemon does not expose per-platform manifest entries (legacy
			// image store). Mutable references and unverified remote descriptors must
			// not override the locally cached image.
			log.Debugf("Image %s is present locally but per-platform descriptor for %s/%s is unavailable", imageRef, targetPlatform.OS, targetPlatform.Architecture)
			return nil, fmt.Errorf(
				"image %q found locally but descriptor for platform %s/%s is unavailable: "+
					"either the platform is not part of this image, or the daemon does not "+
					"expose per-platform manifest entries (enable the containerd image store "+
					"to patch multi-platform images that exist only locally)",
				imageRef, targetPlatform.OS, targetPlatform.Architecture,
			)
		}
	} else {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if lerr != nil {
			log.Debugf("Local platform descriptor lookup for %s failed: %v", imageRef, lerr)
		}

		// Image is not available locally — fall back to the legacy local manifest
		// helper (multi-platform manifest list only) and then to the remote registry.
		desc, err = buildkit.TryGetManifestFromLocalWithContext(ctx, ref)
		if err != nil {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			log.Debugf("Failed to get descriptor from local daemon: %v, trying remote registry", err)
			desc, err = remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
			if err != nil {
				return nil, fmt.Errorf("error fetching descriptor for %q from both local daemon and remote registry: %w", imageRef, err)
			}
			log.Debugf("Successfully fetched descriptor from remote registry for %s", imageRef)
		} else {
			log.Debugf("Successfully fetched descriptor from local daemon for %s", imageRef)
		}
	}

	if pinned, ok := ref.(name.Digest); ok && desc.Digest.String() != pinned.DigestStr() {
		return nil, fmt.Errorf("descriptor for %q does not match the requested digest", imageRef)
	}

	var candidates []v1.Descriptor
	if desc.MediaType.IsIndex() {
		index, err := desc.ImageIndex()
		if err != nil {
			return nil, fmt.Errorf("error getting image index: %w", err)
		}
		manifest, err := index.IndexManifest()
		if err != nil {
			return nil, fmt.Errorf("error getting manifest: %w", err)
		}
		candidates = manifest.Manifests
	} else {
		// Captured platform sources are immutable child manifests. Their
		// platform is in the config, not in a parent index descriptor.
		img, err := desc.Image()
		if err != nil {
			return nil, fmt.Errorf("error getting platform image: %w", err)
		}
		config, err := img.ConfigFile()
		if err != nil {
			return nil, fmt.Errorf("error getting platform image config: %w", err)
		}
		manifest, err := img.Manifest()
		if err != nil {
			return nil, fmt.Errorf("error getting platform image manifest: %w", err)
		}
		candidate := desc.Descriptor
		candidate.Platform = config.Platform()
		candidate.Annotations = manifest.Annotations
		candidates = []v1.Descriptor{candidate}
	}

	// Find the descriptor for the target platform
	for i := range candidates {
		m := &candidates[i]
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
