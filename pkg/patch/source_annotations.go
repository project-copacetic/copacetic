package patch

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
)

var localManifestAnnotations = buildkit.LocalImageManifestAnnotations

// Validate the selected manifest before combining its raw annotations.
// A daemon can name only an index even though all of its children are present.
// Read local metadata through that locator and verify the captured selection;
// requiring the synthesized child name to exist would spuriously go remote.
func captureSourceAnnotations(ctx context.Context, image, child string, descriptor *specs.Descriptor, platform *specs.Platform) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	named, err := reference.ParseNormalizedNamed(child)
	if err != nil {
		return nil, err
	}
	pinned, ok := named.(reference.Digested)
	if !ok {
		return nil, fmt.Errorf("source child is not immutable")
	}
	if descriptor == nil || descriptor.Digest != pinned.Digest() {
		return nil, fmt.Errorf("source child does not match captured descriptor")
	}
	annotations := maps.Clone(descriptor.Annotations)
	if annotations == nil {
		annotations = map[string]string{}
	}
	local, found, err := localPlatformDescriptor(ctx, image, platform)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if found {
		if err != nil {
			return nil, err
		}
		if local == nil {
			// Older Docker APIs cannot expose per-platform descriptors. Recheck
			// the captured identity through the same local-first resolver instead
			// of treating unavailable metadata as evidence of source movement.
			source, err := resolveImageSource(ctx, image)
			if err != nil {
				return nil, fmt.Errorf("recheck local source identity: %w", err)
			}
			if source != nil {
				local = &source.Descriptor
				if source.Index != nil {
					local, err = source.PlatformDescriptor(platform)
					if err != nil {
						return nil, err
					}
				}
			}
		}
		if local == nil || local.Digest != pinned.Digest() {
			return nil, fmt.Errorf("local source platform changed after capture")
		}
		manifestAnnotations, err := localManifestAnnotations(ctx, image, pinned.Digest())
		if err != nil {
			return nil, fmt.Errorf("read captured local manifest annotations: %w", err)
		}
		return buildkit.MergeImageSourceAnnotations(annotations, manifestAnnotations)
	}
	ref, err := name.NewDigest(child)
	if err != nil {
		return nil, err
	}
	fetched, err := remote.Get(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("read captured source manifest: %w", err)
	}
	expected := descriptor.Digest
	if expected.Validate() != nil || !expected.Algorithm().Available() || !v1types.MediaType(descriptor.MediaType).IsImage() ||
		fetched == nil || fetched.Digest.String() != expected.String() || fetched.Size != descriptor.Size ||
		int64(len(fetched.Manifest)) != descriptor.Size || expected.Algorithm().FromBytes(fetched.Manifest) != expected {
		return nil, fmt.Errorf("source manifest does not match captured descriptor")
	}
	var manifest specs.Manifest
	if err := json.Unmarshal(fetched.Manifest, &manifest); err != nil || manifest.SchemaVersion != 2 ||
		(manifest.MediaType != "" && manifest.MediaType != descriptor.MediaType) {
		return nil, fmt.Errorf("source manifest media type does not match captured descriptor")
	}
	return buildkit.MergeImageSourceAnnotations(annotations, manifest.Annotations)
}

// Existing origin metadata is a recovery claim, including partial tuples.
// Check it before exporters replace the tuple with the recovered source.
func validateSourceOriginAnnotations(annotations map[string]string, expected *types.SourceLineage) error {
	_, kind := annotations[types.AnnotationPatchOriginKind]
	_, name := annotations[types.AnnotationPatchOriginName]
	_, dgst := annotations[types.AnnotationPatchOriginDigest]
	if !kind && !name && !dgst {
		return nil
	}
	recorded := types.SourceLineageFromAnnotations(annotations)
	if !recorded.Valid() || !expected.Valid() || recorded.Kind != expected.Kind || recorded.Digest != expected.Digest {
		return fmt.Errorf("source manifest origin contradicts the recovered config origin")
	}
	namesMatch := recorded.Name == expected.Name
	if recorded.Kind == types.PatchOriginImage {
		namesMatch = sameOriginRepository(recorded.Name, expected.Name)
	}
	if !namesMatch {
		return fmt.Errorf("source manifest origin repository contradicts the recovered config origin")
	}
	return nil
}
