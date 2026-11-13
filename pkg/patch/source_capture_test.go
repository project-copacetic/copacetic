package patch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/mocks"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/mock"
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

func TestCaptureSinglePlatformSourceUsesIncompleteLocalIndex(t *testing.T) {
	const immutableCase = "immutable"
	const recordedOriginCase = "recorded origin"
	local, resolver := localSourceIndex, resolveImageSource
	t.Cleanup(func() { localSourceIndex, resolveImageSource = local, resolver })
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	child := digest.FromString("available child")
	root := digest.FromString("original root")
	for _, scenario := range []string{"available", "missing child", recordedOriginCase, immutableCase, sourceAnnotationsCanceled, "invalid root"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			input := "registry.invalid/app:local"
			if scenario == immutableCase {
				input = "registry.invalid/app@" + root.String()
			}
			ref, err := reference.ParseNormalizedNamed(input)
			require.NoError(t, err)
			remoteFailure := errors.New("root unavailable from registry")
			remoteReads := 0
			resolveImageSource = func(context.Context, string) (*buildkit.ImageSource, error) {
				remoteReads++
				return nil, remoteFailure
			}
			localSourceIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
				index := &specs.Index{Manifests: []specs.Descriptor{{Digest: child, Platform: platform}}}
				top := &specs.Descriptor{Digest: root, MediaType: specs.MediaTypeImageIndex}
				switch scenario {
				case "missing child":
					index.Manifests = nil
				case recordedOriginCase:
					index.Annotations = (&types.SourceLineage{Kind: types.PatchOriginImage, Name: input, Digest: root}).Annotations()
				case sourceAnnotationsCanceled:
					cancel()
				case "invalid root":
					top.Digest = ""
				}
				return index, top, false, true, nil
			}
			got, expected, requireManifest, _, _, err := captureSinglePlatformSource(ctx, input, ref, platform)
			switch scenario {
			case "available":
				require.NoError(t, err)
				require.Equal(t, "registry.invalid/app@"+child.String(), got.String())
				require.Equal(t, child, expected)
				require.True(t, requireManifest)
			case "missing child":
				require.ErrorContains(t, err, "no descriptor for platform")
			case recordedOriginCase:
				require.ErrorIs(t, err, errRecordedIndexOrigin)
				require.ErrorIs(t, err, remoteFailure)
			case immutableCase:
				require.ErrorIs(t, err, remoteFailure)
			case sourceAnnotationsCanceled:
				require.ErrorIs(t, err, context.Canceled)
			case "invalid root":
				require.ErrorContains(t, err, "index digest is invalid")
			}
			if scenario == recordedOriginCase || scenario == immutableCase {
				require.Equal(t, 1, remoteReads)
			} else {
				require.Zero(t, remoteReads)
			}
		})
	}
}

func TestPrimeLocalSourceChecksCapturedIdentity(t *testing.T) {
	root, child := digest.FromString("captured root"), digest.FromString("captured child")
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	for _, scenario := range []string{"root", "child", sourceAnnotationsChanged, sourceAnnotationsCanceled} {
		t.Run(scenario, func(t *testing.T) {
			resolved := root
			var failure error
			switch scenario {
			case "child":
				resolved = child
			case sourceAnnotationsChanged:
				resolved = digest.FromString("replacement source")
			case sourceAnnotationsCanceled:
				failure = context.Canceled
			}
			gateway := &mocks.MockGWClient{}
			opt := sourceresolver.Opt{ImageOpt: &sourceresolver.ResolveImageOpt{Platform: platform, ResolveMode: llb.ResolveModePreferLocal.String()}}
			gateway.On("ResolveImageConfig", mock.Anything, "example.com/local:built", opt).Return("example.com/local:built", resolved, []byte(`{}`), failure).Once()
			err := primeLocalSource(t.Context(), &testBuildkitBuildClient{gateway: gateway}, "example.com/local:built", root, child, platform)
			switch scenario {
			case sourceAnnotationsChanged:
				require.ErrorContains(t, err, "changed after capture")
			case sourceAnnotationsCanceled:
				require.ErrorIs(t, err, context.Canceled)
			default:
				require.NoError(t, err)
			}
			gateway.AssertExpectations(t)
		})
	}
}
