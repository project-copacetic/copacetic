package patch

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
)

type indexMetadataReader func(context.Context, string, string, *specs.Platform) (map[string]string, map[string]string, error)

var (
	readIndexChildMetadata indexMetadataReader = readImmutableImageMetadata
	localImageMetadata                         = buildkit.LocalImageMetadata
)

// A recorded parent claim must not contradict any child's recorded origin.
// This is a preflight: platform patchers may export before final index assembly.
// Missing child claims remain unverified and may still omit the output tuple.
func validateRecordedIndexChildren(ctx context.Context, source *multiPlatformSource) error {
	return validateRecordedIndexChildrenWithReader(ctx, source, readIndexChildMetadata)
}

func validateRecordedIndexChildrenWithReader(ctx context.Context, source *multiPlatformSource, read indexMetadataReader) error {
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
		manifest, labels, err := read(ctx, source.Current.Name, ref, child.Platform)
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
func readImmutableImageMetadata(ctx context.Context, parent, image string, _ *specs.Platform) (map[string]string, map[string]string, error) {
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
			return nil, nil, &indexLookupError{error: err}
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
			return nil, nil, &indexLookupError{error: err}
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
	// Read the child's original blobs through the local parent. daemon.Image
	// reconstructs a Docker manifest and cannot prove the captured OCI identity.
	local, config, err := localImageMetadata(ctx, parent, expected)
	if err != nil {
		return nil, nil, err
	}
	if local != nil {
		if digest.FromBytes(local.Manifest) != expected {
			return nil, nil, fmt.Errorf("local manifest does not match immutable reference %s", image)
		}
		var manifest specs.Manifest
		if err := json.Unmarshal(local.Manifest, &manifest); err != nil {
			return nil, nil, err
		}
		if manifest.Config.Digest != digest.FromBytes(config) {
			return nil, nil, fmt.Errorf("local config does not match immutable manifest %s", image)
		}
		var cfg specs.Image
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, nil, err
		}
		return manifest.Annotations, cfg.Config.Labels, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	img, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, nil, &indexLookupError{error: err}
	}
	return inspect(img)
}

// Descriptor equality only proves unchanged content. Docker lists can lose
// index annotations, and legacy children retain their patch marker in config.
// Unavailable metadata leaves this optional common-origin claim unverified.
func unpatchedIndexChild(ctx context.Context, source *buildkit.ImageSource, child *specs.Descriptor) bool {
	ref, err := platformSourceReference(source, child.Platform)
	if err != nil {
		return false
	}
	manifest, labels, err := readIndexChildMetadata(ctx, source.Name, ref, child.Platform)
	if err != nil {
		return false
	}
	for _, values := range []map[string]string{child.Annotations, manifest, labels} {
		for _, key := range []string{
			"BaseImage", types.AnnotationPatchOriginKind, types.AnnotationPatchOriginName, types.AnnotationPatchOriginDigest,
			copaAnnotationKeyPrefix + ".patched", copaAnnotationKeyPrefix + ".image.patched",
		} {
			if _, present := values[key]; present {
				return false
			}
		}
	}
	return true
}
