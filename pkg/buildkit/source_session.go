package buildkit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"

	"github.com/distribution/reference"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

// ResolveImageSourceWithClient captures the source visible to a remote builder
// when the Copa host cannot access its registry. Identity, manifest bytes and
// config are resolved using the same authenticated gateway session.
func ResolveImageSourceWithClient(ctx context.Context, c gwclient.Client, image string, platform *specs.Platform) (*ImageSource, error) {
	r := &gatewayImageResolver{ImageMetaResolver: sourceresolver.NewImageMetaResolver(c), client: c}
	opt := sourceresolver.Opt{ImageOpt: &sourceresolver.ResolveImageOpt{Platform: platform, ResolveMode: llb.ResolveModePreferLocal.String()}}
	_, root, config, err := r.ResolveImageConfig(ctx, image, opt)
	if err != nil {
		return nil, err
	}
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return nil, err
	}
	if root.Validate() != nil {
		return nil, fmt.Errorf("BuildKit returned an invalid source digest")
	}
	if pinned, ok := named.(reference.Digested); ok && pinned.Digest() != root {
		return nil, fmt.Errorf("BuildKit source does not match immutable reference")
	}
	pinned, err := reference.WithDigest(reference.TrimNamed(named), root)
	if err != nil {
		return nil, err
	}
	data, err := r.sourceBlob(ctx, pinned.String())
	if err != nil {
		return nil, err
	}
	if data == nil {
		// The native root is still the exact original image identity, as in
		// the frontend. Older gateways cannot expose manifest/index bytes:
		// retain that root without claiming a separately selected child or
		// copying annotations from an inaccessible client-side lookup.
		return &ImageSource{Name: image, Descriptor: specs.Descriptor{Digest: root}}, nil
	}
	source, err := sourceFromSessionBlob(image, root, data, config)
	if err != nil || source.Index == nil {
		return source, err
	}
	child, err := source.PlatformDescriptor(platform)
	if err != nil {
		return nil, err
	}
	if child.Digest.Validate() != nil || !v1types.MediaType(child.MediaType).IsImage() {
		return nil, fmt.Errorf("BuildKit source platform is not an image manifest")
	}
	childRef, err := reference.WithDigest(reference.TrimNamed(named), child.Digest)
	if err != nil {
		return nil, err
	}
	_, selected, childConfig, err := r.ResolveImageConfig(ctx, childRef.String(), opt)
	if err != nil {
		return nil, err
	}
	if selected != child.Digest || !bytes.Equal(config, childConfig) {
		return nil, fmt.Errorf("BuildKit source platform does not match resolved config")
	}
	childData, err := r.sourceBlob(ctx, childRef.String())
	if err != nil {
		return nil, err
	}
	manifest, err := sourceFromSessionBlob(childRef.String(), child.Digest, childData, childConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid BuildKit source platform manifest: %w", err)
	}
	if manifest.Index != nil {
		return nil, fmt.Errorf("BuildKit source platform is another index")
	}
	for i := range source.Index.Manifests {
		if source.Index.Manifests[i].Digest == child.Digest {
			annotations, err := MergeImageSourceAnnotations(source.Index.Manifests[i].Annotations, manifest.Descriptor.Annotations)
			if err != nil {
				return nil, fmt.Errorf("invalid BuildKit source platform annotations: %w", err)
			}
			source.Index.Manifests[i].Annotations = annotations
		}
	}
	return source, nil
}

func sourceFromSessionBlob(image string, root digest.Digest, data, config []byte) (*ImageSource, error) {
	var index specs.Index
	if err := json.Unmarshal(data, &index); err != nil || index.SchemaVersion != 2 {
		return nil, fmt.Errorf("invalid BuildKit source manifest")
	}
	source := &ImageSource{Name: image, Descriptor: specs.Descriptor{Digest: root, MediaType: index.MediaType, Size: int64(len(data))}}
	if index.Manifests != nil {
		if index.MediaType != "" && !v1types.MediaType(index.MediaType).IsIndex() {
			return nil, fmt.Errorf("BuildKit source index has an invalid media type")
		}
		source.Index = &index
		return source, nil
	}
	var manifest specs.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil || (manifest.MediaType != "" && !v1types.MediaType(manifest.MediaType).IsImage()) {
		return nil, fmt.Errorf("BuildKit source is not an image manifest")
	}
	if manifest.Config.Digest.Validate() != nil || !manifest.Config.Digest.Algorithm().Available() || manifest.Config.Digest.Algorithm().FromBytes(config) != manifest.Config.Digest {
		return nil, fmt.Errorf("BuildKit source manifest does not match resolved config")
	}
	source.Descriptor.Annotations = maps.Clone(manifest.Annotations)
	return source, nil
}
