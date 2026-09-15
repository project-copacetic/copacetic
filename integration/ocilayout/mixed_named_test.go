package ocilayout_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
)

func TestNamedMixedExportKeepsDockerConnection(t *testing.T) {
	if os.Getenv("COPA_OCI_TEST_NAMED") != "1" || os.Getenv("COPA_OCI_TEST_ADDR") == "" {
		t.Skip("requires isolated active buildx, Docker, and COPA_OCI_TEST_NAMED=1")
	}
	// A host-loopback registry is reachable by Docker's worker and unreachable
	// from the separately networked active buildx worker.
	server := httptest.NewServer(registry.New())
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	imageName := "localhost:" + serverURL.Port() + "/copa-1677/fixture:original"
	ref, err := name.NewTag(imageName, name.Insecure)
	require.NoError(t, err)

	var buf bytes.Buffer
	tarWriter := tar.NewWriter(&buf)
	require.NoError(t, tarWriter.WriteHeader(&tar.Header{Name: "source", Mode: 0o644, Size: 6}))
	_, err = tarWriter.Write([]byte("source"))
	require.NoError(t, err)
	require.NoError(t, tarWriter.Close())
	base, err := mutate.AppendLayers(empty.Image, static.NewLayer(buf.Bytes(), v1types.OCIUncompressedLayer))
	require.NoError(t, err)
	var additions []mutate.IndexAddendum
	var configData []byte
	for _, arch := range []string{"amd64", "386"} {
		config, err := base.ConfigFile()
		require.NoError(t, err)
		config.OS, config.Architecture = "linux", arch
		image, err := mutate.ConfigFile(base, config)
		require.NoError(t, err)
		if arch == "amd64" {
			configData, err = json.Marshal(config)
			require.NoError(t, err)
		}
		additions = append(additions, mutate.IndexAddendum{Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
	}
	index := mutate.AppendManifests(empty.Index, additions...)
	require.NoError(t, remote.WriteIndex(ref, index, remote.WithContext(t.Context())))
	platform := ocispec.Platform{OS: "linux", Architecture: "amd64"}
	state := llb.Image(imageName, llb.Platform(platform)).File(llb.Mkfile("/copa-1677-patched", 0o644, []byte("patched")))
	solve := func(ctx context.Context, c *client.Client) error {
		_, err := c.Build(ctx, client.SolveOpt{}, "copa-1677-network-proof", func(ctx context.Context, gateway gwclient.Client) (*gwclient.Result, error) {
			def, err := state.Marshal(ctx)
			if err != nil {
				return nil, err
			}
			return gateway.Solve(ctx, gwclient.SolveRequest{Definition: def.ToPB(), Evaluate: true})
		}, nil)
		return err
	}
	isolated, err := buildkit.NewClient(t.Context(), buildkit.Opts{Addr: os.Getenv("COPA_OCI_TEST_ADDR")})
	require.NoError(t, err)
	defer isolated.Close()
	unreachableCtx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	err = solve(unreachableCtx, isolated)
	cancel()
	require.Error(t, err, "fixture must be unreachable from the other worker's loopback")
	docker, err := buildkit.NewClient(t.Context(), buildkit.Opts{Addr: "docker://"})
	require.NoError(t, err)
	defer docker.Close()
	require.NoError(t, solve(t.Context(), docker), "initial patch state must resolve through Docker")

	original, err := reference.ParseNormalizedNamed(imageName)
	require.NoError(t, err)
	patched, err := reference.WithTag(reference.TrimNamed(original), "patched-amd64")
	require.NoError(t, err)
	output := filepath.Join(t.TempDir(), "output")
	require.NoError(t, buildkit.CreateOCILayoutFromResultsWithOptions(output,
		[]types.PatchResult{{OriginalRef: original, PatchedRef: patched, PatchedState: &state, ConfigData: configData}},
		[]types.PatchPlatform{{Platform: platform}, {Platform: ocispec.Platform{OS: "linux", Architecture: "386"}, ShouldPreserve: true}},
		buildkit.OCILayoutExportOptions{}.WithContext(t.Context()),
	))
	out, err := layout.FromPath(output)
	require.NoError(t, err)
	outIndex, err := out.ImageIndex()
	require.NoError(t, err)
	outManifest, err := outIndex.IndexManifest()
	require.NoError(t, err)
	require.Len(t, outManifest.Manifests, 2)
	originalManifest, err := index.IndexManifest()
	require.NoError(t, err)
	assert.Equal(t, originalManifest.Manifests[1].Digest, outManifest.Manifests[1].Digest)
}
