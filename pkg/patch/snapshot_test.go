package patch

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/moby/buildkit/client"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/require"
)

const (
	originAMD64           = "amd64"
	originManifestSurface = "manifest"
	originConfigSurface   = "config"
)

func TestRecordedIndexInspectsExactChildren(t *testing.T) {
	reader := readIndexChildMetadata
	t.Cleanup(func() { readIndexChildMetadata = reader })
	platform := specs.Platform{OS: "linux", Architecture: originAMD64}
	child := digest.FromString("exact original child")
	parent := &types.SourceLineage{Kind: types.PatchOriginImage, Name: "example.com/app:original", Digest: digest.FromString("original index")}
	source := &multiPlatformSource{
		Current:      &buildkit.ImageSource{Name: "example.com/app:patched", Index: &specs.Index{Manifests: []specs.Descriptor{{Digest: child, Platform: &platform}}}},
		Base:         &buildkit.ImageSource{Index: &specs.Index{Manifests: []specs.Descriptor{{Digest: child, Platform: &platform}}}},
		IndexLineage: parent,
	}
	contradiction := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: parent.Name, Digest: digest.FromString("another origin")}).Annotations()
	for _, surface := range []string{"claim-free", originManifestSurface, originConfigSurface} {
		t.Run(surface, func(t *testing.T) {
			reads := 0
			readIndexChildMetadata = func(_ context.Context, image string) (map[string]string, map[string]string, error) {
				reads++
				require.Equal(t, "example.com/app@"+child.String(), image)
				if surface == originManifestSurface {
					return contradiction, nil, nil
				}
				if surface == originConfigSurface {
					return nil, contradiction, nil
				}
				return nil, nil, nil
			}
			err := validateRecordedIndexChildren(t.Context(), source)
			if surface == "claim-free" {
				require.NoError(t, err, "an exact original needs no BaseImage label")
			} else {
				require.ErrorContains(t, err, "origin contradicts the recorded original index")
			}
			require.Equal(t, 1, reads, "byte equality does not establish consistent origin metadata")
		})
	}
}

func TestPatchMultiPlatformStopsWhenSnapshotUnavailable(t *testing.T) {
	resolver, builder := resolveImageSource, bkNewClient
	t.Cleanup(func() { resolveImageSource, bkNewClient = resolver, builder })
	failure := errors.New("source index metadata unavailable")
	resolveImageSource = func(context.Context, string) (*buildkit.ImageSource, error) { return nil, failure }
	builds := 0
	bkNewClient = func(context.Context, buildkit.Opts) (*client.Client, error) {
		builds++
		return nil, errors.New("platform work must not begin without the snapshot")
	}
	err := patchMultiPlatformImage(t.Context(), &types.Options{Image: "example.com/app:source", PkgTypes: "os", IgnoreError: true, Progress: "quiet"},
		[]types.PatchPlatform{{Platform: specs.Platform{OS: "linux", Architecture: originAMD64}}})
	require.ErrorIs(t, err, failure)
	require.Zero(t, builds)
}

func TestNoUpdatesRetainsCapturedSource(t *testing.T) {
	builder, local := bkNewClient, localPlatformDescriptor
	t.Cleanup(func() { bkNewClient, localPlatformDescriptor = builder, local })
	platform := types.PatchPlatform{Platform: specs.Platform{OS: "linux", Architecture: originAMD64}}
	const input = "example.com/app:moved"
	captured := digest.FromString("captured child")
	source := "example.com/app@" + captured.String()
	for _, stage := range []string{"client construction", "empty report preflight"} {
		t.Run(stage, func(t *testing.T) {
			bkNewClient = func(ctx context.Context, _ buildkit.Opts) (*client.Client, error) {
				if stage == "client construction" {
					return nil, errors.New("BuildKit unavailable")
				}
				return client.New(ctx, "unix://"+t.TempDir()+"/unavailable.sock")
			}
			var lookup string
			localPlatformDescriptor = func(_ context.Context, ref string, p *specs.Platform) (*specs.Descriptor, bool, error) {
				lookup = ref
				d := captured
				if ref != source {
					d = digest.FromString("replacement child after tag move")
				}
				return &specs.Descriptor{Digest: d, Platform: p}, true, nil
			}
			result, err := patchSingleArchImageWithSourceAndUpdates(t.Context(), &types.Options{
				Image: input, Report: "already-parsed", PkgTypes: "os", Progress: "quiet",
			}, platform, true, nil, &unversioned.UpdateManifest{}, source, nil, digest.FromString("captured index"))
			require.ErrorIs(t, err, types.ErrNoUpdatesFound)
			require.NotNil(t, result)
			require.Equal(t, source, lookup)
			require.Equal(t, captured, result.PatchedDesc.Digest)
			require.Equal(t, input, result.OriginalRef.String(), "the original locator still controls output naming")
			require.Equal(t, result.OriginalRef, result.PatchedRef)
		})
	}
}

func TestCapturedSingleManifestDescriptor(t *testing.T) {
	defer stubLocalPlatformDescriptor(t, func(context.Context, string, *specs.Platform) (*specs.Descriptor, bool, error) {
		return nil, false, nil
	})()
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer server.Close()
	ref, err := name.ParseReference(strings.TrimPrefix(server.URL, "http://") + "/snapshot:source")
	require.NoError(t, err)
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: "arm64", Variant: "v8"})
	require.NoError(t, err)
	img = originAnnotatedImage(t, img, map[string]string{"com.example.source": "captured"})
	require.NoError(t, remote.Write(ref, img, remote.WithContext(t.Context())))
	hash, err := img.Digest()
	require.NoError(t, err)
	size, err := img.Size()
	require.NoError(t, err)
	source := ref.Context().Digest(hash.String()).Name()
	for _, arch := range []string{"arm64", originAMD64} {
		t.Run(arch, func(t *testing.T) {
			desc, err := getPlatformDescriptorFromManifest(t.Context(), source, &types.PatchPlatform{Platform: specs.Platform{OS: "linux", Architecture: arch}})
			if arch == originAMD64 {
				require.ErrorContains(t, err, "platform linux/amd64 not found")
				return
			}
			require.NoError(t, err)
			require.Equal(t, hash.String(), desc.Digest.String())
			require.Equal(t, size, desc.Size)
			require.Equal(t, "v8", desc.Platform.Variant)
			require.Equal(t, "captured", desc.Annotations["com.example.source"])
		})
	}
}

func TestPatchMultiPlatformPinsAllSelectionsBeforeWork(t *testing.T) {
	resolver, builder := resolveImageSource, bkNewClient
	t.Cleanup(func() { resolveImageSource, bkNewClient = resolver, builder })
	amd64 := specs.Platform{OS: "linux", Architecture: originAMD64}
	resolveImageSource = func(context.Context, string) (*buildkit.ImageSource, error) {
		return &buildkit.ImageSource{
			Name: "example.com/app:source", Descriptor: specs.Descriptor{Digest: digest.FromString("index")},
			Index: &specs.Index{Manifests: []specs.Descriptor{{Digest: digest.FromString("child"), Platform: &amd64}}},
		}, nil
	}
	builds := 0
	bkNewClient = func(context.Context, buildkit.Opts) (*client.Client, error) {
		builds++
		return nil, errors.New("work started before every selection was pinned")
	}
	err := patchMultiPlatformImage(t.Context(), &types.Options{Image: "example.com/app:source", PkgTypes: "os", IgnoreError: true, Progress: "quiet"},
		[]types.PatchPlatform{{Platform: amd64}, {Platform: specs.Platform{OS: "linux", Architecture: "arm64"}}})
	require.ErrorContains(t, err, "capture source platform linux/arm64")
	require.Zero(t, builds)
}
