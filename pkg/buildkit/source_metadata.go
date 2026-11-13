package buildkit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

// ReadImageMetadataWithClient verifies an immutable manifest and config using
// only the gateway's authenticated source session.
func ReadImageMetadataWithClient(ctx context.Context, c gwclient.Client, image string, platform *specs.Platform) (map[string]string, map[string]string, error) {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return nil, nil, err
	}
	pinned, ok := named.(reference.Digested)
	if !ok {
		return nil, nil, fmt.Errorf("source metadata requires an immutable image reference")
	}
	r := &gatewayImageResolver{ImageMetaResolver: sourceresolver.NewImageMetaResolver(c), client: c}
	_, resolved, config, err := r.ResolveImageConfig(ctx, image, sourceresolver.Opt{ImageOpt: &sourceresolver.ResolveImageOpt{
		Platform: platform, ResolveMode: llb.ResolveModePreferLocal.String(),
	}})
	if err != nil {
		return nil, nil, err
	}
	if resolved != pinned.Digest() {
		return nil, nil, fmt.Errorf("source metadata does not match immutable image reference")
	}
	data, err := r.sourceBlob(ctx, image)
	if err != nil {
		return nil, nil, err
	}
	if data == nil {
		return nil, nil, fmt.Errorf("BuildKit cannot read immutable source manifest metadata")
	}
	source, err := sourceFromSessionBlob(image, resolved, data, config)
	if err != nil {
		return nil, nil, err
	}
	if source.Index != nil {
		return nil, nil, fmt.Errorf("source metadata is an index, not an image manifest")
	}
	var manifest specs.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, err
	}
	if int64(len(config)) != manifest.Config.Size {
		return nil, nil, fmt.Errorf("source config size does not match immutable manifest")
	}
	var cfg specs.Image
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, nil, err
	}
	return manifest.Annotations, cfg.Config.Labels, nil
}
