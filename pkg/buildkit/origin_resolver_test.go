package buildkit

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	specsgo "github.com/opencontainers/image-spec/specs-go"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/mocks"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type originIndexGateway struct {
	gwclient.Client
	unsupported bool
	solve       func(context.Context, gwclient.SolveRequest) (*gwclient.Result, error)
}

func (g *originIndexGateway) BuildOpts() gwclient.BuildOpts {
	if g.unsupported {
		return gwclient.BuildOpts{LLBCaps: pb.Caps.CapSet(nil)}
	}
	return gwclient.BuildOpts{LLBCaps: pb.Caps.CapSet(pb.Caps.All())}
}

//nolint:gocritic // The gateway client interface requires a value request.
func (g *originIndexGateway) Solve(ctx context.Context, req gwclient.SolveRequest) (*gwclient.Result, error) {
	return g.solve(ctx, req)
}

type originIndexReference struct {
	gwclient.Reference
	read func(context.Context, gwclient.ReadRequest) ([]byte, error)
}

func (r *originIndexReference) ReadFile(ctx context.Context, req gwclient.ReadRequest) ([]byte, error) {
	return r.read(ctx, req)
}

func TestRecordedIndexOriginUsesGatewaySession(t *testing.T) {
	oldLocal, oldRemote := tryGetManifestFromLocal, getRemoteImageDescriptor
	t.Cleanup(func() { tryGetManifestFromLocal, getRemoteImageDescriptor = oldLocal, oldRemote })
	tryGetManifestFromLocal = func(context.Context, name.Reference) (*remote.Descriptor, v1.Hash, bool, error) {
		t.Error("native index resolution escaped to the host daemon")
		return nil, v1.Hash{}, false, errors.New("no client-side source")
	}
	getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
		t.Error("native index resolution escaped to the default registry credentials")
		return nil, errors.New("client has no registry credentials")
	}
	platform := &specs.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	child := digest.FromString("selected original")
	config := []byte(`{"os":"linux","architecture":"arm64","config":{"Labels":{}}}`)
	opt := sourceresolver.Opt{ImageOpt: &sourceresolver.ResolveImageOpt{Platform: platform, ResolveMode: llb.ResolveModePreferLocal.String()}}
	denied := errors.New("gateway authentication denied")
	for _, mediaType := range []v1types.MediaType{v1types.OCIImageIndex, v1types.DockerManifestList, ""} {
		t.Run(string(mediaType), func(t *testing.T) {
			for _, scenario := range []string{
				"authenticated", "solve denied", "read canceled", "missing result", "corrupt index",
				"different child", "different platform", "duplicate platform", "non-index", "malformed",
			} {
				t.Run(scenario, func(t *testing.T) {
					index := specs.Index{
						Versioned: specsgo.Versioned{SchemaVersion: 2}, MediaType: string(mediaType),
						Manifests: []specs.Descriptor{{MediaType: specs.MediaTypeImageManifest, Digest: child, Platform: platform}},
					}
					switch scenario {
					case "different child":
						index.Manifests[0].Digest = digest.FromString("different manifest with the same config")
					case "different platform":
						index.Manifests[0].Platform = &specs.Platform{OS: "linux", Architecture: "amd64"}
					case "duplicate platform":
						index.Manifests = append(index.Manifests, index.Manifests[0])
					case "non-index":
						index.MediaType = specs.MediaTypeImageManifest
					}
					data, err := json.Marshal(index)
					require.NoError(t, err)
					if scenario == "malformed" {
						data = []byte("not JSON")
					}
					root := digest.FromBytes(data)
					// A tag plus digest is valid for BaseImage; blob sources must remove the tag.
					ref := "example.com/private:original@" + root.String()
					blobRef := "example.com/private@" + root.String()
					childRef := "example.com/private@" + child.String()
					lineage := &types.SourceLineage{Kind: types.PatchOriginImage, Name: childRef, Digest: child}
					imageResolver := &mocks.MockGWClient{}
					imageResolver.On("ResolveImageConfig", mock.Anything, ref, opt).Return(ref, root, config, nil).Once()
					if scenario == "authenticated" {
						imageResolver.On("ResolveImageConfig", mock.Anything, childRef, opt).Return(childRef, child, config, nil).Once()
					}
					gateway := &originIndexGateway{solve: func(ctx context.Context, request gwclient.SolveRequest) (*gwclient.Result, error) {
						require.Equal(t, t.Context(), ctx)
						require.NotNil(t, request.Definition)
						op := &pb.Op{}
						require.NoError(t, op.UnmarshalVT(request.Definition.Def[0]))
						require.Equal(t, "docker-image+blob://"+blobRef, op.GetSource().Identifier)
						require.Equal(t, "index.json", op.GetSource().Attrs[pb.AttrHTTPFilename])
						if scenario == "solve denied" {
							return nil, denied
						}
						if scenario == "missing result" {
							return nil, nil
						}
						return &gwclient.Result{Ref: &originIndexReference{read: func(ctx context.Context, request gwclient.ReadRequest) ([]byte, error) {
							require.Equal(t, t.Context(), ctx)
							require.Equal(t, "index.json", request.Filename)
							if scenario == "read canceled" {
								return nil, context.Canceled
							}
							if scenario == "corrupt index" {
								return []byte("corrupt index"), nil
							}
							return data, nil
						}}}, nil
					}}
					resolver := &gatewayImageResolver{ImageMetaResolver: imageResolver, client: gateway}
					got, selected, _, err := resolveRecordedOrigin(t.Context(), resolver, ref, lineage, opt)
					switch scenario {
					case "authenticated":
						require.NoError(t, err)
						require.Equal(t, ref, got)
						require.Equal(t, child, selected)
					case "solve denied":
						require.ErrorIs(t, err, denied)
					case "read canceled":
						require.ErrorIs(t, err, context.Canceled)
					default:
						require.Error(t, err)
					}
					require.False(t, opt.ImageOpt.AttestationChain)
					imageResolver.AssertExpectations(t)
				})
			}
		})
	}
}

func TestGatewayOriginIndexCompatibilityFallback(t *testing.T) {
	oldLocal, oldRemote := tryGetManifestFromLocal, getRemoteImageDescriptor
	t.Cleanup(func() { tryGetManifestFromLocal, getRemoteImageDescriptor = oldLocal, oldRemote })
	tryGetManifestFromLocal = func(context.Context, name.Reference) (*remote.Descriptor, v1.Hash, bool, error) {
		return nil, v1.Hash{}, false, errors.New("no local source")
	}
	data := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
	root := digest.FromBytes(data)
	hash, err := v1.NewHash(root.String())
	require.NoError(t, err)
	ref := "example.com/compatibility@" + root.String()
	hostReads := 0
	getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
		hostReads++
		return &remote.Descriptor{Descriptor: v1.Descriptor{MediaType: v1types.OCIImageIndex, Digest: hash, Size: int64(len(data))}, Manifest: data}, nil
	}
	gateway := &originIndexGateway{unsupported: true, solve: func(context.Context, gwclient.SolveRequest) (*gwclient.Result, error) {
		t.Fatal("unsupported gateway must not receive a blob solve")
		return nil, nil
	}}
	source, err := resolveOriginIndex(t.Context(), &gatewayImageResolver{client: gateway}, ref)
	require.NoError(t, err)
	require.Equal(t, root, source.Descriptor.Digest)
	require.Equal(t, 1, hostReads)
}
