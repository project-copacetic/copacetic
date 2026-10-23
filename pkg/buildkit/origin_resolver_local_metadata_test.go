package buildkit

import (
	"bytes"
	"context"
	"errors"
	"testing"

	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestGatewaySourceBlobPrefersOriginalLocalMetadata(t *testing.T) {
	for _, kind := range []string{"root-index", "child-manifest"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newLocalMetadataFixture(t)
			selected, expected := fixture.root, fixture.index
			if kind == "child-manifest" {
				selected, expected = fixture.child, fixture.manifest
			}
			ref := "example.com/local:parent@" + selected.Digest.String()
			mockLocalMetadataArchive(t, ref, &fixture.root, fixture.files)
			forbidLocalMetadataRegistry(t)
			solves := 0
			gateway := &originIndexGateway{solve: func(context.Context, gwclient.SolveRequest) (*gwclient.Result, error) {
				solves++
				return nil, errors.New("cold native snapshot cannot access registry")
			}}
			resolver := &gatewayImageResolver{client: gateway}
			data, err := resolver.sourceBlob(t.Context(), ref)
			require.NoError(t, err)
			require.Equal(t, expected, data, "must return the exact original raw bytes")
			require.Equal(t, digest.Digest(selected.Digest.String()), digest.FromBytes(data))
			require.Zero(t, solves, "local content must avoid the native registry/blob solve")
			if kind == "root-index" {
				source, err := resolveOriginIndex(t.Context(), resolver, ref)
				require.NoError(t, err)
				require.Equal(t, selected.Digest.String(), source.Descriptor.Digest.String())
				require.Equal(t, fixture.index, data)
				require.Len(t, source.Index.Manifests, 2, "an unavailable sibling must not require registry access")
				require.Zero(t, solves)
			}
		})
	}
}

func TestGatewaySourceBlobRejectsCorruptLocalMetadata(t *testing.T) {
	for _, scenario := range []string{"index", localMetadataManifestCase, localMetadataConfigCase, localMetadataInspectCase} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newLocalMetadataFixture(t)
			selected := fixture.root
			switch scenario {
			case "index":
				fixture.files[archiveBlobPath(fixture.root.Digest)] = append(fixture.index, ' ')
			case localMetadataManifestCase:
				selected = fixture.child
				fixture.files[archiveBlobPath(fixture.child.Digest)] = append(fixture.manifest, ' ')
			case localMetadataConfigCase:
				selected = fixture.child
				path := archiveBlobPath(fixture.config.Digest)
				fixture.files[path] = bytes.ReplaceAll(fixture.files[path], []byte("linux"), []byte("other"))
			}
			ref := "example.com/local@" + selected.Digest.String()
			mockLocalMetadataArchive(t, ref, &fixture.root, fixture.files)
			forbidLocalMetadataRegistry(t)
			if scenario == localMetadataInspectCase {
				localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
					return nil, nil, false, true, errors.New("native inspect does not match descriptor")
				}
			}
			gateway := &originIndexGateway{solve: func(context.Context, gwclient.SolveRequest) (*gwclient.Result, error) {
				t.Fatal("invalid local originals must not fall through to a native registry fetch")
				return nil, nil
			}}
			data, err := (&gatewayImageResolver{client: gateway}).sourceBlob(t.Context(), ref)
			require.ErrorContains(t, err, "does not match descriptor")
			require.Nil(t, data)
		})
	}
}

func TestGatewaySourceBlobNativeErrorsKeepSessionAuthority(t *testing.T) {
	for _, scenario := range []string{localMetadataDeniedCase, localMetadataCanceledCase, localMetadataReadDeniedCase, "corrupt", "missing-result", "native-success"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := newLocalMetadataFixture(t)
			ref := "example.com/private@" + fixture.root.Digest.String()
			mockLocalMetadataArchive(t, ref, nil, fixture.files)
			forbidLocalMetadataRegistry(t)
			localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
				return nil, nil, false, false, errors.New("host Docker daemon unavailable")
			}
			denied := errors.New("gateway registry authentication denied")
			solves := 0
			gateway := &originIndexGateway{solve: func(context.Context, gwclient.SolveRequest) (*gwclient.Result, error) {
				solves++
				switch scenario {
				case localMetadataDeniedCase:
					return nil, denied
				case localMetadataCanceledCase:
					return nil, context.Canceled
				case "missing-result":
					return nil, nil
				}
				return &gwclient.Result{Ref: &originIndexReference{read: func(context.Context, gwclient.ReadRequest) ([]byte, error) {
					if scenario == localMetadataReadDeniedCase {
						return nil, denied
					}
					if scenario == "corrupt" {
						return append(fixture.index, ' '), nil
					}
					return fixture.index, nil
				}}}, nil
			}}
			source, err := resolveOriginIndex(t.Context(), &gatewayImageResolver{client: gateway}, ref)
			switch scenario {
			case "native-success":
				require.NoError(t, err)
				require.Equal(t, fixture.root.Digest.String(), source.Descriptor.Digest.String())
			case localMetadataDeniedCase, localMetadataReadDeniedCase:
				require.ErrorIs(t, err, denied)
			case localMetadataCanceledCase:
				require.ErrorIs(t, err, context.Canceled)
			default:
				require.Error(t, err)
			}
			require.Equal(t, 1, solves)
		})
	}
}

func TestGatewaySourceBlobCompatibilityAndCancellation(t *testing.T) {
	fixture := newLocalMetadataFixture(t)
	mockLocalMetadataArchive(t, "unused", nil, fixture.files)
	localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
		t.Fatal("unsupported or already canceled gateways must not inspect local metadata")
		return nil, nil, false, false, nil
	}
	gateway := &originIndexGateway{unsupported: true, solve: func(context.Context, gwclient.SolveRequest) (*gwclient.Result, error) {
		t.Fatal("unsupported or already canceled gateways must not solve blob sources")
		return nil, nil
	}}
	resolver := &gatewayImageResolver{client: gateway}
	data, err := resolver.sourceBlob(t.Context(), "example.com/local@"+fixture.root.Digest.String())
	require.NoError(t, err)
	require.Nil(t, data)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, unsupported := range []bool{false, true} {
		gateway.unsupported = unsupported
		data, err = resolver.sourceBlob(ctx, "example.com/local@"+fixture.root.Digest.String())
		require.ErrorIs(t, err, context.Canceled)
		require.Nil(t, data)
	}
}

func TestLocalImageMetadataInvalidSelection(t *testing.T) {
	fixture := newLocalMetadataFixture(t)
	mockLocalMetadataArchive(t, "unused", nil, fixture.files)
	localImageIndex = func(context.Context, string) (*specs.Index, *specs.Descriptor, bool, bool, error) {
		t.Fatal("invalid selections must fail before accessing the daemon")
		return nil, nil, false, false, nil
	}
	for _, selected := range []digest.Digest{"", "invalid", digest.Digest("unknown:" + fixture.root.Digest.Hex)} {
		got, config, err := LocalImageMetadata(t.Context(), "unused", selected)
		require.Error(t, err)
		require.Nil(t, got)
		require.Nil(t, config)
	}
}
