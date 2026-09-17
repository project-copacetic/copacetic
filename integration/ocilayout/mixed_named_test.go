package ocilayout_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	"github.com/moby/buildkit/util/progress/progressui"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/patch"
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

func TestNamedSinglePatchKeepsDockerConnection(t *testing.T) {
	if os.Getenv("COPA_OCI_TEST_NAMED") != "1" || os.Getenv("COPA_OCI_TEST_ADDR") == "" {
		t.Skip("requires isolated active buildx, Docker, and COPA_OCI_TEST_NAMED=1")
	}
	server := httptest.NewServer(registry.New())
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	imageName := fmt.Sprintf("localhost:%s/copa-1677/single-%d:original", serverURL.Port(), time.Now().UnixNano())
	ref, err := name.NewTag(imageName, name.Insecure)
	require.NoError(t, err)
	baseRef, err := name.ParseReference(alpineIndex)
	require.NoError(t, err)
	base, err := remote.Image(baseRef, remote.WithPlatform(v1.Platform{OS: linuxOS, Architecture: amd64Arch}), remote.WithContext(t.Context()))
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, base, remote.WithContext(t.Context())))

	isolated, err := buildkit.NewClient(t.Context(), buildkit.Opts{Addr: os.Getenv("COPA_OCI_TEST_ADDR")})
	require.NoError(t, err)
	defer isolated.Close()
	unreachableCtx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	_, err = isolated.Build(unreachableCtx, client.SolveOpt{}, "copa-1677-single-network-proof", func(ctx context.Context, gateway gwclient.Client) (*gwclient.Result, error) {
		def, err := llb.Image(imageName, llb.Platform(ocispec.Platform{OS: linuxOS, Architecture: amd64Arch})).Marshal(ctx)
		if err != nil {
			return nil, err
		}
		return gateway.Solve(ctx, gwclient.SolveRequest{Definition: def.ToPB(), Evaluate: true})
	}, nil)
	cancel()
	require.Error(t, err, "the active buildx worker must not resolve the Docker-accessible source")

	for _, address := range []string{"", "docker://"} {
		t.Run("address="+address, func(t *testing.T) {
			patchedName := strings.TrimSuffix(imageName, ":original") + ":patched"
			t.Cleanup(func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				data, err := exec.CommandContext(cleanupCtx, "docker", "image", "rm", patchedName).CombinedOutput()
				assert.NoError(t, err, "remove only the unique image loaded by this test: %s", data)
			})
			output := filepath.Join(t.TempDir(), "output")
			err := patch.Patch(t.Context(), &types.Options{
				Image: imageName, OCIDir: output, PatchedTag: "patched", Report: writeReport(t, amd64Arch),
				Scanner: "trivy", PkgTypes: "os", LibraryPatchLevel: "patch", Format: "openvex",
				BkAddr: address, Timeout: 4 * time.Minute, Progress: progressui.QuietMode,
			})
			data, inspectErr := exec.CommandContext(t.Context(), "docker", "image", "inspect", patchedName).CombinedOutput()
			require.NoError(t, inspectErr, "patch/load must complete before the OCI export result is checked: %s", data)
			require.NoError(t, err)
			out, err := layout.FromPath(output)
			require.NoError(t, err)
			index, err := out.ImageIndex()
			require.NoError(t, err)
			manifest, err := index.IndexManifest()
			require.NoError(t, err)
			require.Len(t, manifest.Manifests, 1)
			image, err := index.Image(manifest.Manifests[0].Digest)
			require.NoError(t, err)
			config, err := image.ConfigFile()
			require.NoError(t, err)
			assert.Equal(t, linuxOS, config.OS)
			assert.Equal(t, amd64Arch, config.Architecture)
			reader := mutate.Extract(image)
			defer reader.Close()
			archive := tar.NewReader(reader)
			found := false
			for {
				header, err := archive.Next()
				if err == io.EOF {
					break
				}
				require.NoError(t, err)
				if strings.TrimPrefix(header.Name, "/") != "lib/apk/db/installed" {
					continue
				}
				installed, err := io.ReadAll(archive)
				require.NoError(t, err)
				for _, record := range strings.Split(string(installed), "\n\n") {
					if strings.Contains("\n"+record, "\nP:busybox\n") {
						found = true
						assert.NotContains(t, record, "V:1.37.0-r8\n", "the exported image must contain the patched package")
					}
				}
			}
			require.True(t, found, "read the actual exported busybox package record")
		})
	}
}
