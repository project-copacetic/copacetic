package patch

import (
	"archive/tar"
	"bytes"
	"context"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/require"
)

type movingOriginGateway struct {
	gwclient.Client
	source string
	move   func() error
	moved  bool
}

func (g *movingOriginGateway) ResolveSourceMetadata(ctx context.Context, op *pb.SourceOp, opt sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
	result, err := g.Client.ResolveSourceMetadata(ctx, op, opt)
	if err == nil && op.Identifier == "docker-image://"+g.source && !g.moved {
		g.moved = true
		if err := g.move(); err != nil {
			return nil, err
		}
	}
	return result, err
}

func testSourceLocatorRaces(t *testing.T, ctx context.Context, bk *client.Client, addr, repo string, original v1.Image, application map[string]string) {
	t.Helper()
	t.Run("mutable-direct-source", func(t *testing.T) {
		input, output := repo+":direct-capture", repo+":direct-capture-output"
		require.NoError(t, remote.Write(originTestReference(t, input), original, remote.WithContext(ctx)))
		expected, err := original.Digest()
		require.NoError(t, err)
		resolver := resolveImageSource
		t.Cleanup(func() { resolveImageSource = resolver })
		captured := 0
		resolveImageSource = func(ctx context.Context, image string) (*buildkit.ImageSource, error) {
			source, err := resolver(ctx, image)
			if err != nil || image != input {
				return source, err
			}
			captured++
			config, err := original.ConfigFile()
			require.NoError(t, err)
			config = config.DeepCopy()
			config.Config.Labels["com.example.direct-source"] = "replacement"
			replacement, err := mutate.ConfigFile(original, config)
			require.NoError(t, err)
			replacement = originAnnotatedImage(t, replacement, map[string]string{"com.example.direct-source": "replacement"})
			require.NoError(t, remote.Write(originTestReference(t, input), replacement, remote.WithContext(ctx)))
			return source, nil
		}
		require.NoError(t, Patch(ctx, &types.Options{
			Image: input, Report: originTestReport(t, originAMD64), Scanner: "trivy", Push: true, PatchedTag: output,
			BkAddr: addr, PkgTypes: "os", Progress: "quiet", Timeout: 2 * time.Minute,
		}))
		require.Equal(t, 1, captured)
		image, err := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
		require.NoError(t, err)
		config, err := image.ConfigFile()
		require.NoError(t, err)
		require.Equal(t, expected.String(), config.Config.Labels[types.AnnotationPatchOriginDigest])
		require.NotContains(t, config.Config.Labels, "com.example.direct-source")
		manifest, err := image.Manifest()
		require.NoError(t, err)
		require.NotContains(t, manifest.Annotations, "com.example.direct-source")
		for key, value := range application {
			require.Equal(t, value, manifest.Annotations[key])
		}
		verifyOriginBlobs(t, image)
	})
	t.Run("recorded-origin-race", func(t *testing.T) {
		input, base, output := repo+":racing-p1", repo+":racing-original", repo+":racing-p2"
		require.NoError(t, remote.Write(originTestReference(t, base), original, remote.WithContext(ctx)))
		first, err := remote.Image(originTestReference(t, repo+":p1-amd64"), remote.WithContext(ctx))
		require.NoError(t, err)
		config, err := first.ConfigFile()
		require.NoError(t, err)
		config = config.DeepCopy()
		config.Config.Labels["BaseImage"] = base
		first, err = mutate.ConfigFile(first, config)
		require.NoError(t, err)
		require.NoError(t, remote.Write(originTestReference(t, input), first, remote.WithContext(ctx)))
		var archive bytes.Buffer
		writer := tar.NewWriter(&archive)
		content := []byte("replacement source must never be patched")
		require.NoError(t, writer.WriteHeader(&tar.Header{Name: "copa-race-marker", Mode: 0o644, Size: int64(len(content))}))
		_, err = writer.Write(content)
		require.NoError(t, err)
		require.NoError(t, writer.Close())
		layer := static.NewLayer(archive.Bytes(), v1types.OCIUncompressedLayer)
		replacement, err := mutate.AppendLayers(original, layer)
		require.NoError(t, err)
		build, err := createBuildConfig(output, true, true, nil, application, "p2", "", false)
		require.NoError(t, err)
		build.SolveOpt.Exports[0].Attrs["registry.insecure"] = attrValueTrue
		var gateway *movingOriginGateway
		_, err = bk.Build(ctx, build.SolveOpt, "copa-origin-race-test", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
			gateway = &movingOriginGateway{Client: c, source: base, move: func() error {
				return remote.Write(originTestReference(t, base), replacement, remote.WithContext(ctx))
			}}
			result, err := ExecutePatchCore(&Context{Context: ctx, Client: gateway}, &Options{
				ImageName: input, TargetPlatform: &types.PatchPlatform{Platform: platformSpec("linux", originAMD64, "")}, WorkingFolder: t.TempDir(),
				Updates: &unversioned.UpdateManifest{
					Metadata:  unversioned.Metadata{OS: unversioned.OS{Type: "alpine", Version: "3.20.0"}, Config: unversioned.Config{Arch: originAMD64}},
					OSUpdates: unversioned.UpdatePackages{{Name: "busybox", InstalledVersion: "1.36.1-r29", FixedVersion: "1.36.1-r29"}},
				},
			})
			if err != nil {
				return nil, err
			}
			return result.Result, nil
		}, nil)
		require.NoError(t, err)
		require.True(t, gateway.moved)
		image, err := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
		require.NoError(t, err)
		manifest, err := image.Manifest()
		require.NoError(t, err)
		originalManifest, err := original.Manifest()
		require.NoError(t, err)
		require.Len(t, manifest.Layers, len(originalManifest.Layers)+1, "re-patch must use original A and one replacement patch layer")
		for i := range originalManifest.Layers {
			require.Equal(t, originalManifest.Layers[i].Digest, manifest.Layers[i].Digest)
		}
		expected, err := original.Digest()
		require.NoError(t, err)
		config, err = image.ConfigFile()
		require.NoError(t, err)
		require.Equal(t, expected.String(), config.Config.Labels[types.AnnotationPatchOriginDigest])
		verifyOriginBlobs(t, image)
	})
}
