package buildkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/containerd/errdefs"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/go-digest"
)

// LocalImageMetadata reads an original manifest or index and, for an image, its
// original config through the locally named parent. Selected must identify the
// archive root or one of its children. Manifest bytes are never re-marshaled.
// An unpulled selected blob, missing source or classic store returns nil, nil, nil; invalid
// native metadata and cancellation return errors without consulting a registry.
func LocalImageMetadata(ctx context.Context, parentImage string, selected digest.Digest) (*remote.Descriptor, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := selected.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid selected local manifest: %w", err)
	}
	if !selected.Algorithm().Available() {
		return nil, nil, fmt.Errorf("selected local manifest uses an unavailable digest algorithm")
	}
	_, native, _, found, err := localImageIndex(ctx, parentImage)
	if canceled := localMetadataCancellation(ctx, err); canceled != nil {
		return nil, nil, canceled
	}
	if err != nil {
		if found {
			return nil, nil, fmt.Errorf("inspect original local image metadata: %w", err)
		}
		return nil, nil, nil
	}
	if !found {
		return nil, nil, nil
	}
	if native == nil {
		keepsManifests, err := localImageStoreKeepsManifests(ctx)
		if canceled := localMetadataCancellation(ctx, err); canceled != nil {
			return nil, nil, canceled
		}
		if err != nil || !keepsManifests {
			return nil, nil, nil
		}
	}
	stream, err := localImageArchive(ctx, parentImage)
	if stream != nil {
		defer stream.Close()
	}
	if canceled := localMetadataCancellation(ctx, err); canceled != nil {
		return nil, nil, canceled
	}
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("save original local image metadata: %w", err)
	}
	if stream == nil {
		return nil, nil, fmt.Errorf("local native image save returned no archive")
	}
	archive, err := readLocalArchive(ctx, stream, true)
	if canceled := localMetadataCancellation(ctx, err); canceled != nil {
		return nil, nil, canceled
	}
	if err != nil {
		return nil, nil, err
	}
	if archive == nil {
		return nil, nil, fmt.Errorf("local native image archive has no original manifest index")
	}
	if native != nil && (native.Digest.String() != archive.root.Digest.String() ||
		native.Size != archive.root.Size || native.MediaType != string(archive.root.MediaType)) {
		return nil, nil, fmt.Errorf("local image archive root does not match inspected descriptor")
	}
	return archive.selectedMetadata(selected)
}

// Some Docker errors carry cancellation even before ctx.Err is observable.
func localMetadataCancellation(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

func (a *localArchiveMetadata) selectedMetadata(selected digest.Digest) (*remote.Descriptor, []byte, error) {
	chosen, data := a.root, a.manifest
	if chosen.Digest.String() != selected.String() {
		var index v1.IndexManifest
		if !chosen.MediaType.IsIndex() {
			return nil, nil, fmt.Errorf("local image archive does not contain selected manifest %s", selected)
		}
		if err := json.Unmarshal(data, &index); err != nil {
			return nil, nil, fmt.Errorf("parse local source index: %w", err)
		}
		chosen = v1.Descriptor{}
		for i := range index.Manifests {
			if index.Manifests[i].Digest.String() == selected.String() {
				chosen = index.Manifests[i]
				break
			}
		}
		if chosen.Digest.String() != selected.String() {
			return nil, nil, fmt.Errorf("local image archive does not contain selected manifest %s", selected)
		}
		if (!chosen.MediaType.IsImage() && !chosen.MediaType.IsIndex()) || chosen.Size <= 0 {
			return nil, nil, fmt.Errorf("local image archive has an invalid selected manifest descriptor")
		}
		if _, present := a.present[archiveBlobPath(chosen.Digest)]; !present {
			return nil, nil, nil // The exact root references an unpulled child.
		}
		var err error
		data, err = archiveManifest(a.blobs, &chosen)
		if err != nil {
			return nil, nil, err
		}
	}
	if chosen.MediaType.IsIndex() {
		var index v1.IndexManifest
		if err := json.Unmarshal(data, &index); err != nil || index.Manifests == nil {
			return nil, nil, fmt.Errorf("local image archive has an invalid source index")
		}
		chosen.Annotations = index.Annotations
		return &remote.Descriptor{Descriptor: chosen, Manifest: data}, nil, nil
	}
	var manifest v1.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, fmt.Errorf("parse local source manifest: %w", err)
	}
	if !manifest.Config.MediaType.IsConfig() {
		return nil, nil, fmt.Errorf("local image archive has an invalid config media type")
	}
	configDigest := digest.Digest(manifest.Config.Digest.String())
	if configDigest.Validate() != nil || !configDigest.Algorithm().Available() || manifest.Config.Size <= 0 {
		return nil, nil, fmt.Errorf("local image archive has an invalid config descriptor")
	}
	if _, present := a.present[archiveBlobPath(manifest.Config.Digest)]; !present {
		return nil, nil, nil // Its immutable config may not have been pulled yet.
	}
	config, err := archiveBlob(a.blobs, &manifest.Config, "config")
	if err != nil {
		return nil, nil, err
	}
	var metadata v1.ConfigFile
	if err := json.Unmarshal(config, &metadata); err != nil || metadata.OS == "" || metadata.Architecture == "" {
		return nil, nil, fmt.Errorf("local image archive has an invalid image config")
	}
	chosen.Annotations = manifest.Annotations
	return &remote.Descriptor{Descriptor: chosen, Manifest: data}, config, nil
}
