package buildkit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/distribution/reference"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

// Keep index recovery on the gateway that owns registry authentication and
// network access. The image adapter alone hides the native blob source.
type gatewayImageResolver struct {
	sourceresolver.ImageMetaResolver
	client gwclient.Client
}

// resolveSourceIndex returns nil only when the server lacks the blob source.
// Native lookup and validation errors must not trigger another auth path.
func (r *gatewayImageResolver) resolveSourceIndex(ctx context.Context, ref string) (*ImageSource, error) {
	buildOpts := r.client.BuildOpts()
	if err := buildOpts.LLBCaps.Supports(pb.CapSourceImageBlob); err != nil {
		return nil, nil
	}
	named, err := reference.ParseNormalizedNamed(ref)
	if err != nil {
		return nil, fmt.Errorf("parse original index reference: %w", err)
	}
	pinned, ok := named.(reference.Digested)
	if !ok {
		return nil, fmt.Errorf("original index reference must contain a digest")
	}
	root := pinned.Digest()
	if root.Validate() != nil || !root.Algorithm().Available() {
		return nil, fmt.Errorf("original index reference has an invalid digest")
	}
	// Blob sources require an untagged digest reference. Unlike image metadata,
	// this source returns the exact bytes of OCI indexes and Docker lists alike.
	blobRef, err := reference.WithDigest(reference.TrimNamed(named), root)
	if err != nil {
		return nil, err
	}
	definition, err := llb.ImageBlob(blobRef.String(), llb.Filename("index.json")).Marshal(ctx, llb.WithCaps(buildOpts.LLBCaps))
	if err != nil {
		return nil, fmt.Errorf("prepare original index blob: %w", err)
	}
	result, err := r.client.Solve(ctx, gwclient.SolveRequest{Definition: definition.ToPB()})
	if err != nil {
		return nil, fmt.Errorf("resolve original index through BuildKit source session: %w", err)
	}
	if result == nil || result.Ref == nil {
		return nil, fmt.Errorf("BuildKit source session returned no original index")
	}
	data, err := result.Ref.ReadFile(ctx, gwclient.ReadRequest{Filename: "index.json"})
	if err != nil {
		return nil, fmt.Errorf("read original index through BuildKit source session: %w", err)
	}
	if root.Algorithm().FromBytes(data) != root {
		return nil, fmt.Errorf("BuildKit source index content does not match its digest")
	}
	var index specs.Index
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("parse BuildKit source index: %w", err)
	}
	if index.SchemaVersion != 2 || index.Manifests == nil || (index.MediaType != "" && !v1types.MediaType(index.MediaType).IsIndex()) {
		return nil, fmt.Errorf("BuildKit source content is not an image index")
	}
	return &ImageSource{Name: ref, Descriptor: specs.Descriptor{Digest: root, MediaType: index.MediaType, Size: int64(len(data))}, Index: &index}, nil
}

func resolveOriginIndex(ctx context.Context, resolver sourceresolver.ImageMetaResolver, ref string) (*ImageSource, error) {
	if native, ok := resolver.(interface {
		resolveSourceIndex(context.Context, string) (*ImageSource, error)
	}); ok {
		index, err := native.resolveSourceIndex(ctx, ref)
		if err != nil || index != nil {
			return index, err
		}
	}
	// Retain compatibility where the gateway lacks the native blob source.
	return ResolveImageSource(ctx, ref)
}
