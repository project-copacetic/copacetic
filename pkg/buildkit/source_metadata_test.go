package buildkit

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	specsgo "github.com/opencontainers/image-spec/specs-go"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestReadImageMetadataWithClient(t *testing.T) {
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	config := []byte(`{"os":"linux","architecture":"amd64","config":{"Labels":{"BaseImage":"example.com/app:original"}}}`)
	for _, scenario := range []string{"exact", "wrong config", "wrong size", "wrong digest", "corrupt manifest", "unavailable manifest", "old gateway"} {
		t.Run(scenario, func(t *testing.T) {
			manifest := specs.Manifest{
				Versioned: specsgo.Versioned{SchemaVersion: 2}, MediaType: specs.MediaTypeImageManifest,
				Config:      specs.Descriptor{MediaType: specs.MediaTypeImageConfig, Digest: digest.FromBytes(config), Size: int64(len(config))},
				Annotations: map[string]string{"com.example.manifest": "preserved"},
			}
			if scenario == "wrong config" {
				manifest.Config.Digest = digest.FromString("wrong config")
			}
			if scenario == "wrong size" {
				manifest.Config.Size++
			}
			data, err := json.Marshal(manifest)
			require.NoError(t, err)
			root := digest.FromBytes(data)
			image := "example.com/app@" + root.String()
			gateway := &sourceSessionGateway{originIndexGateway: &originIndexGateway{unsupported: scenario == "old gateway"}}
			gateway.metadata = func(op *pb.SourceOp, opt sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
				require.Equal(t, "docker-image://"+image, op.Identifier)
				require.Equal(t, platform, opt.ImageOpt.Platform)
				selected := root
				if scenario == "wrong digest" {
					selected = digest.FromString("different manifest")
				}
				return &sourceresolver.MetaResponse{Op: op, Image: &sourceresolver.ResolveImageResponse{Digest: selected, Config: config}}, nil
			}
			gateway.solve = func(context.Context, gwclient.SolveRequest) (*gwclient.Result, error) {
				if scenario == "unavailable manifest" {
					return nil, context.Canceled
				}
				return &gwclient.Result{Ref: &originIndexReference{read: func(context.Context, gwclient.ReadRequest) ([]byte, error) {
					if scenario == "corrupt manifest" {
						return []byte(`{}`), nil
					}
					return data, nil
				}}}, nil
			}
			annotations, labels, err := ReadImageMetadataWithClient(t.Context(), gateway, image, platform)
			if scenario != "exact" {
				require.Error(t, err)
				if scenario == "unavailable manifest" {
					require.ErrorIs(t, err, context.Canceled)
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, manifest.Annotations, annotations)
			require.Equal(t, map[string]string{"BaseImage": "example.com/app:original"}, labels)
		})
	}
}
