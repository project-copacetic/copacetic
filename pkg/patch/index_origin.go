package patch

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
)

var readIndexChildMetadata = readImmutableImageMetadata

// A recorded parent claim must not contradict any child's recorded origin.
// This is a preflight: platform patchers may export before final index assembly.
// Missing child claims remain unverified and may still omit the output tuple.
func validateRecordedIndexChildren(ctx context.Context, source *multiPlatformSource) error {
	for i := range source.Current.Index.Manifests {
		child := &source.Current.Index.Manifests[i]
		if child.Platform == nil || child.Platform.OS == "unknown" || child.Platform.Architecture == "unknown" {
			continue
		}
		expected, expectedErr := source.Base.PlatformDescriptor(child.Platform)
		check := func(values map[string]string) error {
			_, kind := values[types.AnnotationPatchOriginKind]
			_, name := values[types.AnnotationPatchOriginName]
			_, dgst := values[types.AnnotationPatchOriginDigest]
			if !kind && !name && !dgst {
				return nil
			}
			lineage := sourceLineageFromAnnotations(values)
			if expectedErr != nil || !lineage.Valid() || lineage.Kind != source.IndexLineage.Kind ||
				!sameOriginRepository(lineage.Name, source.IndexLineage.Name) || (lineage.Digest != expected.Digest && lineage.Digest != source.IndexLineage.Digest) {
				return fmt.Errorf("platform %s origin contradicts the recorded original index", buildkit.PlatformKey(*child.Platform))
			}
			return nil
		}
		if err := check(child.Annotations); err != nil {
			return err
		}
		ref, err := platformSourceReference(source.Current, child.Platform)
		if err != nil {
			return err
		}
		manifest, labels, err := readIndexChildMetadata(ctx, ref)
		if err != nil {
			return fmt.Errorf("inspect platform %s origin: %w", buildkit.PlatformKey(*child.Platform), err)
		}
		if err := check(manifest); err != nil {
			return err
		}
		if err := check(labels); err != nil {
			return err
		}
		// An exact original child needs no BaseImage label, but its recorded
		// metadata above must still agree. A different manifest cannot
		// satisfy a recorded index claim merely by having no origin labels.
		// Legacy patched children still have an unverified BaseImage locator.
		if labels["BaseImage"] == "" && (expectedErr != nil || child.Digest != expected.Digest) {
			return fmt.Errorf("platform %s unpatched manifest contradicts the recorded original index", buildkit.PlatformKey(*child.Platform))
		}
	}
	return nil
}

// Read only an immutable manifest/config pair. A daemon reconstruction may not
// reproduce the source manifest bytes; fallback is safe only at the same digest.
func readImmutableImageMetadata(ctx context.Context, image string) (map[string]string, map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	ref, err := name.NewDigest(image)
	if err != nil {
		return nil, nil, err
	}
	expected := digest.Digest(ref.DigestStr())
	inspect := func(img v1.Image) (map[string]string, map[string]string, error) {
		raw, err := img.RawManifest()
		if err != nil {
			return nil, nil, err
		}
		if digest.FromBytes(raw) != expected {
			return nil, nil, fmt.Errorf("manifest does not match immutable reference %s", image)
		}
		var manifest specs.Manifest
		if err := json.Unmarshal(raw, &manifest); err != nil {
			return nil, nil, err
		}
		config, err := img.RawConfigFile()
		if err != nil {
			return nil, nil, err
		}
		if digest.FromBytes(config) != manifest.Config.Digest {
			return nil, nil, fmt.Errorf("config does not match immutable manifest %s", image)
		}
		var cfg specs.Image
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, nil, err
		}
		return manifest.Annotations, cfg.Config.Labels, nil
	}
	if img, err := daemon.Image(ref, daemon.WithContext(ctx)); err == nil {
		if manifest, labels, err := inspect(img); err == nil {
			return manifest, labels, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	img, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, nil, err
	}
	return inspect(img)
}
