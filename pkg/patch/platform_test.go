package patch

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
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
