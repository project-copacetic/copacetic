package patch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestSingleSourceCaptureFailureStopsPatch(t *testing.T) {
	builder, workers, resolver := bkNewClient, listWorkers, resolveImageSource
	t.Cleanup(func() { bkNewClient, listWorkers, resolveImageSource = builder, workers, resolver })
	platform := specs.Platform{OS: "linux", Architecture: "amd64"}
	bkNewClient = func(ctx context.Context, _ buildkit.Opts) (*client.Client, error) {
		return client.New(ctx, "unix://"+t.TempDir()+"/absent.sock")
	}
	listWorkers = func(context.Context, *client.Client) ([]*client.WorkerInfo, error) {
		return []*client.WorkerInfo{{ID: "source-capture-test", Platforms: []specs.Platform{platform}}}, nil
	}
	failure := errors.New("source snapshot unavailable")
	resolveImageSource = func(context.Context, string) (*buildkit.ImageSource, error) { return nil, failure }
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result, err := patchSingleArchImage(ctx, &types.Options{Image: "127.0.0.1:1/app:source", PkgTypes: "os", Progress: "quiet", Push: true}, types.PatchPlatform{Platform: platform}, false, nil)
	require.ErrorIs(t, err, failure)
	require.Nil(t, result)
}
