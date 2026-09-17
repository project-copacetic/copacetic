package buildkit

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	dockerclient "github.com/moby/moby/client"
	"github.com/opencontainers/go-digest"
)

// Older containerd-backed Docker daemons omit descriptors from inspect, but
// save the original OCI manifests. Reading those bytes avoids inventing an
// identity from Docker-save's compatibility manifest.json representation.
var localArchiveDescriptor = descriptorFromLocalArchive

type localArchiveError struct{ error }

func (err *localArchiveError) Unwrap() error { return err.error }

func descriptorFromLocalArchive(ctx context.Context, image string) (*remote.Descriptor, error) {
	cli, err := dockerclient.New(dockerclient.FromEnv)
	if err != nil {
		return nil, err
	}
	defer cli.Close()
	stream, err := cli.ImageSave(ctx, []string{image})
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	return readArchiveDescriptor(ctx, stream)
}

func readArchiveDescriptor(ctx context.Context, stream io.Reader) (*remote.Descriptor, error) {
	// Retain only small manifest JSON, never image layers or extracted paths.
	const indexFile = "index.json"
	const maxManifestSize = 4 << 20
	const maxMetadataSize = 32 << 20
	blobs := map[string][]byte{}
	var index []byte
	var total int64
	reader := tar.NewReader(stream)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read local image archive: %w", err)
		}
		if header.Name == indexFile && (!header.FileInfo().Mode().IsRegular() || header.Size > maxManifestSize) {
			return nil, fmt.Errorf("local image archive has an invalid index entry")
		}
		if !header.FileInfo().Mode().IsRegular() || (header.Name != indexFile && !strings.HasPrefix(header.Name, "blobs/")) || header.Size > maxManifestSize {
			continue
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		var manifest v1.IndexManifest
		if json.Unmarshal(data, &manifest) != nil || manifest.SchemaVersion != 2 {
			if header.Name == indexFile {
				return nil, fmt.Errorf("local image archive has an invalid index")
			}
			continue
		}
		total += int64(len(data))
		if total > maxMetadataSize {
			return nil, fmt.Errorf("local image archive manifest metadata exceeds %d bytes", maxMetadataSize)
		}
		if header.Name == indexFile {
			if index != nil {
				return nil, fmt.Errorf("local image archive has multiple indexes")
			}
			index = data
		} else {
			if _, exists := blobs[header.Name]; exists {
				return nil, fmt.Errorf("local image archive has duplicate manifest %q", header.Name)
			}
			blobs[header.Name] = data
		}
	}
	if index == nil {
		return nil, nil // Classic Docker-save archives have no OCI identity.
	}
	var roots v1.IndexManifest
	if err := json.Unmarshal(index, &roots); err != nil || len(roots.Manifests) != 1 || (roots.MediaType != "" && !roots.MediaType.IsIndex()) {
		return nil, fmt.Errorf("local image archive must identify exactly one source")
	}
	root := roots.Manifests[0]
	data, err := archiveManifest(blobs, &root)
	if err != nil {
		return nil, err
	}
	// The archive's wrapper annotations are Docker locators, not source
	// manifest annotations. Preserve only metadata from the actual source.
	var metadata v1.IndexManifest
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}
	root.Annotations = metadata.Annotations
	if root.MediaType.IsIndex() {
		for i := range metadata.Manifests {
			child := &metadata.Manifests[i]
			if !child.MediaType.IsImage() {
				continue
			}
			if _, present := blobs[archiveBlobPath(child.Digest)]; !present {
				continue // Exact index bytes may reference unavailable siblings.
			}
			body, err := archiveManifest(blobs, child)
			if err != nil {
				return nil, err
			}
			var manifest v1.Manifest
			if err := json.Unmarshal(body, &manifest); err != nil {
				return nil, err
			}
			child.Annotations, err = MergeImageSourceAnnotations(child.Annotations, manifest.Annotations)
			if err != nil {
				return nil, err
			}
		}
		// Add locally read child metadata without recomputing the captured
		// root identity; all original index descriptors remain intact.
		data, err = json.Marshal(metadata)
		if err != nil {
			return nil, err
		}
	}
	return &remote.Descriptor{Descriptor: root, Manifest: data}, nil
}

func archiveBlobPath(hash v1.Hash) string {
	return "blobs/" + hash.Algorithm + "/" + hash.Hex
}

func archiveManifest(blobs map[string][]byte, desc *v1.Descriptor) ([]byte, error) {
	hash := digest.Digest(desc.Digest.String())
	if hash.Validate() != nil || !hash.Algorithm().Available() || (!desc.MediaType.IsImage() && !desc.MediaType.IsIndex()) {
		return nil, fmt.Errorf("local image archive has an invalid manifest descriptor")
	}
	data, ok := blobs[archiveBlobPath(desc.Digest)]
	if !ok || int64(len(data)) != desc.Size || hash.Algorithm().FromBytes(data) != hash {
		return nil, fmt.Errorf("local image archive manifest does not match descriptor %s", hash)
	}
	var manifest struct {
		SchemaVersion int               `json:"schemaVersion"`
		MediaType     v1types.MediaType `json:"mediaType"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.SchemaVersion != 2 || (manifest.MediaType != "" && manifest.MediaType != desc.MediaType) {
		return nil, fmt.Errorf("local image archive manifest has an invalid media type")
	}
	return data, nil
}
