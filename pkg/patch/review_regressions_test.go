package patch

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestReportDirectoryAcceptsSingleManifest(t *testing.T) {
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	defer server.Close()
	input := strings.TrimPrefix(server.URL, "http://") + "/single:source"
	ref, err := name.NewTag(input)
	require.NoError(t, err)
	image, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "linux", Architecture: "amd64"})
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, image, remote.WithContext(t.Context())))
	dgst, err := image.Digest()
	require.NoError(t, err)
	size, err := image.Size()
	require.NoError(t, err)

	originalResolver, originalBuilder := resolveImageSource, bkNewClient
	t.Cleanup(func() { resolveImageSource, bkNewClient = originalResolver, originalBuilder })
	resolveImageSource = func(_ context.Context, got string) (*buildkit.ImageSource, error) {
		require.Equal(t, input, got)
		return &buildkit.ImageSource{Name: input, Registry: true, Descriptor: specs.Descriptor{Digest: digest.Digest(dgst.String()), MediaType: imageMediaType(t, image), Size: size}}, nil
	}
	ready := errors.New("reached BuildKit origin preflight")
	builds := 0
	bkNewClient = func(context.Context, buildkit.Opts) (*client.Client, error) {
		builds++
		return nil, ready
	}
	reports := t.TempDir()
	report, err := os.ReadFile(originTestReport(t, "amd64"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(reports, "amd64.json"), report, 0o600))
	err = Patch(t.Context(), &types.Options{Image: input, Report: reports, Scanner: "trivy", PkgTypes: "os", Progress: "quiet", Timeout: 10 * time.Second})
	require.ErrorIs(t, err, ready)
	require.Equal(t, 1, builds)
}

func imageMediaType(t *testing.T, image v1.Image) string {
	t.Helper()
	mediaType, err := image.MediaType()
	require.NoError(t, err)
	return string(mediaType)
}

func TestGatewayIndexRecoveryKeepsSourceAccess(t *testing.T) {
	originalResolver, originalReader := resolveImageSource, readIndexChildMetadata
	t.Cleanup(func() { resolveImageSource, readIndexChildMetadata = originalResolver, originalReader })
	resolveImageSource = func(context.Context, string) (*buildkit.ImageSource, error) {
		t.Fatal("gateway recovery must not use host registry resolution")
		return nil, nil
	}
	readIndexChildMetadata = func(context.Context, localSource, string, string, *specs.Platform) (map[string]string, map[string]string, error) {
		t.Fatal("gateway recovery must not read metadata through the host")
		return nil, nil, nil
	}
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	root, originalChild, patchedChild := digest.FromString("original index"), digest.FromString("original child"), digest.FromString("patched child")
	lineage := &types.SourceLineage{Kind: types.PatchOriginImage, Name: "example.com/app:original", Digest: root}
	current := &buildkit.ImageSource{Name: "example.com/app:patched", Descriptor: specs.Descriptor{Digest: digest.FromString("patched index")}, Index: &specs.Index{
		Annotations: lineage.Annotations(), Manifests: []specs.Descriptor{{Platform: platform, Digest: patchedChild}},
	}}
	original := &buildkit.ImageSource{Name: "example.com/app@" + root.String(), Descriptor: specs.Descriptor{Digest: root}, Index: &specs.Index{
		Manifests: []specs.Descriptor{{Platform: platform, Digest: originalChild}},
	}}
	childOrigin := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: lineage.Name, Digest: originalChild}).Annotations()
	reads := 0
	access := sourceAccess{
		resolve: func(_ context.Context, image string) (*buildkit.ImageSource, error) {
			require.Equal(t, original.Name, image)
			return original, nil
		},
		readMetadata: func(_ context.Context, _ localSource, parent, image string, got *specs.Platform) (map[string]string, map[string]string, error) {
			reads++
			require.Equal(t, current.Name, parent)
			require.Equal(t, "example.com/app@"+patchedChild.String(), image)
			require.Equal(t, platform, got)
			return childOrigin, map[string]string{"BaseImage": lineage.Name}, nil
		},
	}
	ref, err := reference.ParseNormalizedNamed(current.Name)
	require.NoError(t, err)
	pinned, selected, _, _, _, err := singlePlatformSnapshotWithAccess(t.Context(), current, ref, platform, access)
	require.NoError(t, err)
	require.Equal(t, patchedChild, selected)
	require.Equal(t, "example.com/app@"+patchedChild.String(), pinned.String())
	require.Equal(t, 1, reads)

	access.readMetadata = func(context.Context, localSource, string, string, *specs.Platform) (map[string]string, map[string]string, error) {
		return (&types.SourceLineage{Kind: types.PatchOriginImage, Name: lineage.Name, Digest: digest.FromString("contradiction")}).Annotations(), nil, nil
	}
	_, _, _, _, _, err = singlePlatformSnapshotWithAccess(t.Context(), current, ref, platform, access)
	require.ErrorIs(t, err, errRecordedIndexOrigin)
}

type failingSourceConfigGateway struct{ gwclient.Client }

func (failingSourceConfigGateway) ResolveSourceMetadata(context.Context, *pb.SourceOp, sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
	return nil, errors.New("temporary source config I/O failure")
}

func TestOrdinaryConfigFailureDoesNotBecomeOriginFailure(t *testing.T) {
	_, err := initializePatchConfig(t.Context(), failingSourceConfigGateway{}, &Options{
		ImageName:      "example.com/app@" + digest.FromString("fresh source").String(),
		TargetPlatform: &types.PatchPlatform{Platform: specs.Platform{OS: "linux", Architecture: "amd64"}},
	}, nil)
	require.ErrorContains(t, err, "temporary source config I/O failure")
	require.NotErrorIs(t, err, errOriginIntegrity)
	loaderErr := errors.New("loader unavailable")
	require.ErrorIs(t, selectPatchWaitError(loaderErr, err), loaderErr)
}

func TestIndexRecoveryAccessFailureRetainsCapturedSnapshot(t *testing.T) {
	previousResolver, previousReader := resolveImageSource, readIndexChildMetadata
	t.Cleanup(func() { resolveImageSource, readIndexChildMetadata = previousResolver, previousReader })
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	originalRoot, originalChild := digest.FromString("original index"), digest.FromString("original child")
	currentChild := digest.FromString("captured current child")
	lineage := &types.SourceLineage{Kind: types.PatchOriginImage, Name: "example.com/app:original", Digest: originalRoot}
	current := &buildkit.ImageSource{Name: "example.com/app:current", Descriptor: specs.Descriptor{Digest: digest.FromString("captured current index")}, Index: &specs.Index{
		Annotations: lineage.Annotations(), Manifests: []specs.Descriptor{{Digest: currentChild, Platform: platform}},
	}}
	original := &buildkit.ImageSource{Name: "example.com/app@" + originalRoot.String(), Descriptor: specs.Descriptor{Digest: originalRoot}, Index: &specs.Index{
		Manifests: []specs.Descriptor{{Digest: originalChild, Platform: platform}},
	}}
	ref, err := reference.ParseNormalizedNamed(current.Name)
	require.NoError(t, err)
	for _, scenario := range []string{"original access", "child access", "contradiction", "wrong original digest"} {
		t.Run(scenario, func(t *testing.T) {
			captures := 0
			resolveImageSource = func(_ context.Context, image string) (*buildkit.ImageSource, error) {
				if image == current.Name {
					captures++
					return current, nil
				}
				require.Equal(t, original.Name, image)
				if scenario == "original access" {
					return nil, errors.New("original requires gateway authentication")
				}
				if scenario == "wrong original digest" {
					wrong := *original
					wrong.Descriptor.Digest = digest.FromString("unexpected original")
					return &wrong, nil
				}
				return original, nil
			}
			readIndexChildMetadata = func(context.Context, localSource, string, string, *specs.Platform) (map[string]string, map[string]string, error) {
				if scenario == "child access" {
					return nil, nil, &indexLookupError{error: errors.New("child requires gateway authentication")}
				}
				return (&types.SourceLineage{Kind: types.PatchOriginImage, Name: lineage.Name, Digest: digest.FromString("contradiction")}).Annotations(), nil, nil
			}
			_, _, _, _, _, err := captureSinglePlatformSource(t.Context(), current.Name, ref, platform)
			require.ErrorIs(t, err, errRecordedIndexOrigin)
			require.Equal(t, 1, captures)
			var lookup *indexLookupError
			if scenario == "contradiction" || scenario == "wrong original digest" {
				require.NotErrorAs(t, err, &lookup, "integrity failures must not become retryable access failures")
				return
			}
			require.ErrorAs(t, err, &lookup)
			require.Same(t, current, lookup.source, "gateway retry must reuse the captured current index")
			access := sourceAccess{
				resolve: func(_ context.Context, image string) (*buildkit.ImageSource, error) {
					require.Equal(t, original.Name, image, "never resolve the current tag again")
					return original, nil
				},
				readMetadata: func(context.Context, localSource, string, string, *specs.Platform) (map[string]string, map[string]string, error) {
					return (&types.SourceLineage{Kind: types.PatchOriginImage, Name: lineage.Name, Digest: originalChild}).Annotations(), map[string]string{"BaseImage": lineage.Name}, nil
				},
			}
			_, selected, _, root, _, err := singlePlatformSnapshotWithAccess(t.Context(), lookup.source, ref, platform, access)
			require.NoError(t, err)
			require.Equal(t, currentChild, selected)
			require.Equal(t, current.Descriptor.Digest, root)
		})
	}
}
