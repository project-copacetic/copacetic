package patch

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	remotev1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	remoteTypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/types"
)

// stubLocalPlatformDescriptor swaps the package-level localPlatformDescriptor
// var with a fake for the duration of a test. It returns a cleanup func.
func stubLocalPlatformDescriptor(
	t *testing.T,
	fn func(ctx context.Context, imageRef string, p *ispec.Platform) (*ispec.Descriptor, bool, error),
) func() {
	t.Helper()
	orig := localPlatformDescriptor
	localPlatformDescriptor = fn
	return func() { localPlatformDescriptor = orig }
}

func stubVerifiedRemoteIndex(
	t *testing.T,
	fn func(ref name.Digest) (*remote.Descriptor, error),
) func() {
	t.Helper()
	orig := getVerifiedRemoteIndex
	getVerifiedRemoteIndex = fn
	return func() { getVerifiedRemoteIndex = orig }
}

func platformTestRemoteIndexDescriptor(indexDigest string) *remote.Descriptor {
	raw := []byte(`{
		"schemaVersion":2,
		"mediaType":"application/vnd.oci.image.index.v1+json",
		"manifests":[
			{
				"mediaType":"application/vnd.oci.image.manifest.v1+json",
				"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"size":123,
				"platform":{"os":"linux","architecture":"amd64"}
			},
			{
				"mediaType":"application/vnd.oci.image.manifest.v1+json",
				"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				"size":456,
				"platform":{"os":"linux","architecture":"arm64"}
			}
		]
	}`)
	return &remote.Descriptor{
		Descriptor: remotev1.Descriptor{
			MediaType: remoteTypes.OCIImageIndex,
			Size:      int64(len(raw)),
			Digest:    remotev1.Hash{Algorithm: "sha256", Hex: indexDigest},
		},
		Manifest: raw,
	}
}

// TestGetPlatformDescriptorFromManifest_LocalHit verifies that when the local
// daemon returns a descriptor, the function returns it directly without
// attempting any remote registry lookup.
func TestGetPlatformDescriptorFromManifest_LocalHit(t *testing.T) {
	want := &ispec.Descriptor{
		MediaType: ispec.MediaTypeImageManifest,
		Digest:    digest.Digest("sha256:" + strings.Repeat("a", 64)),
		Size:      4321,
	}

	defer stubLocalPlatformDescriptor(t, func(_ context.Context, _ string, p *ispec.Platform) (*ispec.Descriptor, bool, error) {
		require.NotNil(t, p)
		require.Equal(t, "linux", p.OS)
		require.Equal(t, "arm64", p.Architecture)
		return want, true, nil
	})()

	got, err := getPlatformDescriptorFromManifest(
		"127.0.0.1:1/example:latest",
		&types.PatchPlatform{Platform: ispec.Platform{OS: "linux", Architecture: "arm64"}},
	)
	require.NoError(t, err)
	require.Same(t, want, got)
}

// TestGetPlatformDescriptorFromManifest_LocalDigestUsesVerifiedRemoteIndex
// reproduces a legacy daemon exposing only the locally cached child of a remote
// index. Discovery has already accepted the immutable remote index, so
// preserved-platform descriptor lookup must apply the same verified fallback.
func TestGetPlatformDescriptorFromManifest_LocalDigestUsesVerifiedRemoteIndex(t *testing.T) {
	const indexDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	imageRef := "example.com/test/image@sha256:" + indexDigest

	defer stubLocalPlatformDescriptor(t, func(_ context.Context, _ string, _ *ispec.Platform) (*ispec.Descriptor, bool, error) {
		return nil, true, nil
	})()
	defer stubVerifiedRemoteIndex(t, func(ref name.Digest) (*remote.Descriptor, error) {
		require.Equal(t, "sha256:"+indexDigest, ref.DigestStr())
		return platformTestRemoteIndexDescriptor(indexDigest), nil
	})()

	got, err := getPlatformDescriptorFromManifest(
		imageRef,
		&types.PatchPlatform{Platform: ispec.Platform{OS: "linux", Architecture: "arm64"}},
	)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, digest.Digest("sha256:"+strings.Repeat("b", 64)), got.Digest)
	assert.Equal(t, int64(456), got.Size)
	require.NotNil(t, got.Platform)
	assert.Equal(t, "arm64", got.Platform.Architecture)
}

// TestGetPlatformDescriptorFromManifest_LocalAmbiguous verifies the error
// surfaced when the local daemon found the image but did not return a
// per-platform descriptor. This happens when either (a) the requested platform
// is not part of this image, or (b) the daemon uses the legacy (non-containerd)
// image store. The error message must cover BOTH cases — previously it only
// blamed the legacy snapshotter, which misleads users whose image legitimately
// lacks the requested platform.
//
// Critical contract assertion: the function must NOT fall back to remote in
// this case. The test stub purposely makes a remote fallthrough impossible by
// also failing the legacy TryGetManifestFromLocal/remote.Get path with a
// connection-refused-style reference; if the function silently fell through,
// the test would surface the wrong error string.
func TestGetPlatformDescriptorFromManifest_LocalAmbiguous(t *testing.T) {
	defer stubLocalPlatformDescriptor(t, func(_ context.Context, _ string, _ *ispec.Platform) (*ispec.Descriptor, bool, error) {
		return nil, true, nil // ok=true, no descriptor — the ambiguous case
	})()
	defer stubVerifiedRemoteIndex(t, func(name.Digest) (*remote.Descriptor, error) {
		t.Fatal("mutable local image reference must not be reconciled with a remote image")
		return nil, nil
	})()

	_, err := getPlatformDescriptorFromManifest(
		"127.0.0.1:1/example:latest",
		&types.PatchPlatform{Platform: ispec.Platform{OS: "linux", Architecture: "ppc64le"}},
	)
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, `image "127.0.0.1:1/example:latest"`)
	require.Contains(t, msg, "linux/ppc64le")
	require.Contains(t, msg, "platform is not part of this image", "error must mention the missing-platform case")
	require.Contains(t, msg, "containerd image store", "error must mention the legacy-snapshotter case")
	// Must NOT mention any remote-registry attempt — the contract is that
	// when the image is found locally, copa does not silently hit the network.
	require.NotContains(t, msg, "remote registry", "must not fall back to remote when image is found locally")
}

// TestGetPlatformDescriptorFromManifest_LocalErrorFallsThrough verifies that
// when LocalPlatformDescriptor returns ok=false (image not in local daemon),
// the function falls through to the legacy local-then-remote path. We don't
// fully exercise the legacy path here (that would require an actual
// daemon/registry), but we assert the fall-through is reached by checking
// the surfaced error mentions the remote fetch.
func TestGetPlatformDescriptorFromManifest_LocalErrorFallsThrough(t *testing.T) {
	defer stubLocalPlatformDescriptor(t, func(_ context.Context, _ string, _ *ispec.Platform) (*ispec.Descriptor, bool, error) {
		return nil, false, errors.New("simulated: image not in local daemon")
	})()

	_, err := getPlatformDescriptorFromManifest(
		"127.0.0.1:1/example:latest",
		&types.PatchPlatform{Platform: ispec.Platform{OS: "linux", Architecture: "amd64"}},
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "from both local daemon and remote registry",
		"with ok=false, the function must fall through to the legacy local-then-remote path")
}
