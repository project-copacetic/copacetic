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

// Containerd-backed Docker daemons older than API 1.48 omit descriptors from
// inspect, but save the original OCI manifests. Reading those bytes avoids
// inventing an identity from Docker-save's compatibility manifest.json
// representation. Classic graph-driver stores never reach this reader: their
// saved index describes a reconstructed manifest.
var (
	localArchiveDescriptor = descriptorFromLocalArchive
	localImageArchive      = openLocalImageArchive
)

type localArchiveError struct{ error }

func (err *localArchiveError) Unwrap() error { return err.error }

// errLocalManifestUnavailable means the local daemon has the image but cannot
// provide its original manifest, so the source identity comes from a registry.
var errLocalManifestUnavailable = errors.New("local image store does not keep original manifests")

func descriptorFromLocalArchive(ctx context.Context, image string) (*remote.Descriptor, error) {
	return descriptorFromLocalArchiveForManifest(ctx, image, "")
}

// LocalImageManifestAnnotations reads the exact selected manifest through its
// locally named parent. It never replaces missing local bytes with a registry
// lookup. Classic Docker-save archives have no native manifest annotations.
func LocalImageManifestAnnotations(ctx context.Context, image string, selected digest.Digest) (map[string]string, error) {
	if err := selected.Validate(); err != nil {
		return nil, fmt.Errorf("invalid selected local manifest: %w", err)
	}
	desc, err := descriptorFromLocalArchiveForManifest(ctx, image, selected)
	if err != nil || desc == nil {
		return nil, err
	}
	return desc.Annotations, nil
}

func descriptorFromLocalArchiveForManifest(ctx context.Context, image string, selected digest.Digest) (*remote.Descriptor, error) {
	stream, err := localImageArchive(ctx, image)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	return readArchiveDescriptorForManifest(ctx, stream, selected)
}

type localArchiveStream struct {
	io.ReadCloser
	client *dockerclient.Client
}

func (s *localArchiveStream) Close() error {
	return errors.Join(s.ReadCloser.Close(), s.client.Close())
}

func openLocalImageArchive(ctx context.Context, image string) (io.ReadCloser, error) {
	cli, err := dockerclient.New(dockerclient.FromEnv)
	if err != nil {
		return nil, err
	}
	stream, err := cli.ImageSave(ctx, []string{image})
	if err != nil {
		cli.Close()
		return nil, err
	}
	return &localArchiveStream{ReadCloser: stream, client: cli}, nil
}

type localArchiveMetadata struct {
	present  map[string]struct{}
	blobs    map[string][]byte
	root     v1.Descriptor
	manifest []byte
}

// readLocalArchive shares the bounded streaming reader between identity and
// exact metadata lookups. Only the latter needs to retain image configs.
func readLocalArchive(ctx context.Context, stream io.Reader, includeConfigs bool) (*localArchiveMetadata, error) {
	// Retain only bounded manifest/config JSON, never layers or extracted paths.
	const indexFile = "index.json"
	const maxManifestSize = 4 << 20
	const maxMetadataSize = 32 << 20
	blobs := map[string][]byte{}
	present := map[string]struct{}{}
	var index []byte
	var total int64
	reader := tar.NewReader(&contextReader{ctx: ctx, reader: stream})
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
		if includeConfigs && strings.HasPrefix(header.Name, "blobs/") {
			// A presence marker distinguishes an unpulled blob from corrupt,
			// oversized or non-JSON bytes. Never retain image-layer payloads.
			total += int64(len(header.Name))
			if total > maxMetadataSize {
				return nil, fmt.Errorf("local image archive metadata exceeds %d bytes", maxMetadataSize)
			}
			if _, exists := present[header.Name]; exists && !header.FileInfo().IsDir() {
				return nil, fmt.Errorf("local image archive has duplicate manifest or config blob %q", header.Name)
			}
			present[header.Name] = struct{}{}
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
			var config v1.ConfigFile
			if !includeConfigs || json.Unmarshal(data, &config) != nil || config.OS == "" || config.Architecture == "" {
				continue
			}
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
	return &localArchiveMetadata{present: present, blobs: blobs, root: root, manifest: data}, nil
}

func readArchiveDescriptor(ctx context.Context, stream io.Reader) (*remote.Descriptor, error) {
	return readArchiveDescriptorForManifest(ctx, stream, "")
}

func readArchiveDescriptorForManifest(ctx context.Context, stream io.Reader, selected digest.Digest) (*remote.Descriptor, error) {
	archive, err := readLocalArchive(ctx, stream, false)
	if err != nil || archive == nil {
		return nil, err
	}
	blobs, root, data := archive.blobs, archive.root, archive.manifest
	// The archive's wrapper annotations are Docker locators, not source
	// manifest annotations. Preserve only metadata from the actual source.
	var metadata v1.IndexManifest
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}
	root.Annotations = metadata.Annotations
	if selected != "" {
		chosen := root
		if root.MediaType.IsIndex() {
			chosen = v1.Descriptor{}
			for i := range metadata.Manifests {
				child := &metadata.Manifests[i]
				if child.Digest.String() == selected.String() {
					chosen = *child
					break
				}
			}
		}
		if chosen.Digest.String() != selected.String() || !chosen.MediaType.IsImage() {
			return nil, fmt.Errorf("local image archive does not contain selected manifest %s", selected)
		}
		body, err := archiveManifest(blobs, &chosen)
		if err != nil {
			return nil, err
		}
		var manifest v1.Manifest
		if err := json.Unmarshal(body, &manifest); err != nil {
			return nil, err
		}
		// Return raw body annotations for validation against the separately
		// captured descriptor, without hiding a partial tuple.
		chosen.Annotations = manifest.Annotations
		return &remote.Descriptor{Descriptor: chosen, Manifest: body}, nil
	}
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

func archiveBlob(blobs map[string][]byte, desc *v1.Descriptor, kind string) ([]byte, error) {
	hash := digest.Digest(desc.Digest.String())
	if hash.Validate() != nil || !hash.Algorithm().Available() {
		return nil, fmt.Errorf("local image archive has an invalid %s descriptor", kind)
	}
	data, ok := blobs[archiveBlobPath(desc.Digest)]
	if !ok || int64(len(data)) != desc.Size || hash.Algorithm().FromBytes(data) != hash {
		return nil, fmt.Errorf("local image archive %s does not match descriptor %s", kind, hash)
	}
	return data, nil
}

func archiveManifest(blobs map[string][]byte, desc *v1.Descriptor) ([]byte, error) {
	if !desc.MediaType.IsImage() && !desc.MediaType.IsIndex() {
		return nil, fmt.Errorf("local image archive has an invalid manifest descriptor")
	}
	data, err := archiveBlob(blobs, desc, "manifest")
	if err != nil {
		return nil, err
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
