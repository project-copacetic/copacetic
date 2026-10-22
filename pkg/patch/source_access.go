package patch

import (
	"context"

	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
)

// indexLookupError retains an already captured current index when recovery
// access fails. A gateway retry must validate this snapshot, not resolve its tag
// again. Shape, digest and contradictory-origin errors do not use this marker.
type indexLookupError struct {
	error
	source *buildkit.ImageSource
}

func (err *indexLookupError) Unwrap() error { return err.error }

// Keep recovery and child validation on the same access path as source capture.
// A gateway-only registry must never fall back to the host's network or auth.
type sourceAccess struct {
	resolve      func(context.Context, string) (*buildkit.ImageSource, error)
	readMetadata indexMetadataReader
}

func gatewaySourceAccess(c gwclient.Client, platform *specs.Platform) sourceAccess {
	return sourceAccess{
		resolve: func(ctx context.Context, image string) (*buildkit.ImageSource, error) {
			return buildkit.ResolveImageSourceWithClient(ctx, c, image, platform)
		},
		readMetadata: func(ctx context.Context, _, image string, platform *specs.Platform) (map[string]string, map[string]string, error) {
			return buildkit.ReadImageMetadataWithClient(ctx, c, image, platform)
		},
	}
}
