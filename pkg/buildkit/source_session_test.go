package buildkit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	specsgo "github.com/opencontainers/image-spec/specs-go"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

type sourceSessionGateway struct {
	*originIndexGateway
	metadata func(*pb.SourceOp, sourceresolver.Opt) (*sourceresolver.MetaResponse, error)
}

func (g *sourceSessionGateway) ResolveSourceMetadata(_ context.Context, op *pb.SourceOp, opt sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
	return g.metadata(op, opt)
}

func TestSourceSessionCapture(t *testing.T) {
	const indexCase = "index"
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	config := []byte(`{"os":"linux","architecture":"amd64","config":{"Labels":{}}}`)
	for _, scenario := range []string{"manifest", indexCase, "corrupt blob", "wrong config", "wrong child", "canceled", "old server"} {
		t.Run(scenario, func(t *testing.T) {
			manifest := specs.Manifest{
				Versioned: specsgo.Versioned{SchemaVersion: 2}, MediaType: specs.MediaTypeImageManifest,
				Config: specs.Descriptor{Digest: digest.FromBytes(config), Size: int64(len(config))}, Annotations: map[string]string{"com.example.manifest": "preserved"},
			}
			if scenario == "wrong config" {
				manifest.Config.Digest = digest.FromString("another config")
			}
			data, err := json.Marshal(manifest)
			require.NoError(t, err)
			child := digest.FromBytes(data)
			root := child
			blobs := map[digest.Digest][]byte{child: data}
			if scenario == indexCase || scenario == "wrong child" {
				index := specs.Index{
					Versioned: specsgo.Versioned{SchemaVersion: 2}, MediaType: specs.MediaTypeImageIndex,
					Manifests: []specs.Descriptor{{Digest: child, MediaType: specs.MediaTypeImageManifest, Platform: platform, Annotations: map[string]string{"com.example.descriptor": "preserved"}}},
				}
				indexData, err := json.Marshal(index)
				require.NoError(t, err)
				root = digest.FromBytes(indexData)
				blobs[root] = indexData
			}
			gateway := &sourceSessionGateway{originIndexGateway: &originIndexGateway{unsupported: scenario == "old server"}}
			gateway.metadata = func(op *pb.SourceOp, opt sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
				require.Equal(t, llb.ResolveModePreferLocal.String(), opt.ImageOpt.ResolveMode)
				require.Equal(t, platform, opt.ImageOpt.Platform)
				require.False(t, opt.ImageOpt.AttestationChain)
				selected := root
				if strings.Contains(op.Identifier, "@") {
					selected = child
					if scenario == "wrong child" {
						selected = digest.FromString("wrong selected child")
					}
				}
				return &sourceresolver.MetaResponse{Op: op, Image: &sourceresolver.ResolveImageResponse{Digest: selected, Config: config}}, nil
			}
			gateway.solve = func(_ context.Context, request gwclient.SolveRequest) (*gwclient.Result, error) {
				if scenario == "canceled" {
					return nil, context.Canceled
				}
				op := &pb.Op{}
				require.NoError(t, op.UnmarshalVT(request.Definition.Def[0]))
				blobDigest := digest.Digest(strings.SplitN(op.GetSource().Identifier, "@", 2)[1])
				return &gwclient.Result{Ref: &originIndexReference{read: func(context.Context, gwclient.ReadRequest) ([]byte, error) {
					if scenario == "corrupt blob" {
						return []byte("corrupt"), nil
					}
					return blobs[blobDigest], nil
				}}}, nil
			}
			oldLocal, oldRemote := tryGetManifestFromLocal, getRemoteImageDescriptor
			t.Cleanup(func() { tryGetManifestFromLocal, getRemoteImageDescriptor = oldLocal, oldRemote })
			tryGetManifestFromLocal = func(context.Context, name.Reference) (*remote.Descriptor, v1.Hash, bool, error) {
				t.Fatal("gateway source capture must not require host metadata access")
				return nil, v1.Hash{}, false, errors.New("not local")
			}
			getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
				t.Fatal("gateway source capture must not require client registry access")
				return nil, errors.New("client source inaccessible")
			}
			source, err := ResolveImageSourceWithClient(t.Context(), gateway, "example.com/source:mutable", platform)
			switch scenario {
			case "manifest", indexCase, "old server":
				require.NoError(t, err)
				require.Equal(t, root, source.Descriptor.Digest)
				if scenario == indexCase {
					selected, err := source.PlatformDescriptor(platform)
					require.NoError(t, err)
					require.Equal(t, child, selected.Digest)
					require.Equal(t, "preserved", selected.Annotations["com.example.manifest"])
					require.Equal(t, "preserved", selected.Annotations["com.example.descriptor"])
				}
			case "canceled":
				require.ErrorIs(t, err, context.Canceled)
			default:
				require.Error(t, err)
			}
		})
	}
}
