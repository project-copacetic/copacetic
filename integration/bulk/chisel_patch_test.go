package integration

import (
	"archive/tar"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	debversion "github.com/knqyf263/go-deb-version"
	"github.com/project-copacetic/copacetic/internal/testutil/chiselverify"
	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed config-chisel.yaml
var chiselConfigTemplate string

const (
	canonicalNativeChiselImage = "docker.io/ubuntu/dotnet-runtime:8.0-24.04_stable_145@sha256:20bd739a82b977ad1fc882d0a73be15df8db4ad04c9cee210ba2572fdc273351"
	communityNativeChiselImage = "ghcr.io/hadrienpatte/sonarr@sha256:d506fff2fe6ca5a7a02f7303c3014a9911e50299d17774e0d3b64ed8a244fa1f"
	defaultChiselRelease       = "https://github.com/canonical/chisel-releases.git#ca7ad8113998470ff77231af799c363c4a48feca"
	imageChiselRelease         = "ubuntu-24.04"
	expectedChiselVersion      = "v1.4.2"
	chiselReleaseAnnotation    = "sh.copa.chisel.release"
	chiselVersionAnnotation    = "sh.copa.chisel.version"
)

type bulkChiselImageState struct {
	config              *v1.ConfigFile
	manifestAnnotations map[string]string
	manifest            *copachisel.Manifest
}

// TestBulkChiselReleaseDefaultAndPerImageOverride validates that bulk patching
// applies the top-level Chisel release by default while honoring an image-level
// named release override. The distinct provenance values prove that neither the
// top-level default nor the per-image override was replaced by release inference.
// Both source fixtures are immutable native-Chisel images that are old enough
// to require a comprehensive re-cut. This test intentionally lives with the
// bulk integration suite because its subject is bulk configuration precedence
// and propagation; the Chisel e2e suite separately covers image patch behavior.
func TestBulkChiselReleaseDefaultAndPerImageOverride(t *testing.T) {
	t.Setenv("GODEBUG", "netdns=go+netgo")
	ctx := context.Background()

	regContainer, registryHost, err := startLocalRegistry(ctx)
	require.NoError(t, err, "failed to start local registry")
	defer func() {
		if err := regContainer.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}()

	defaultRepo := fmt.Sprintf("%s/chisel/default-release", registryHost)
	overrideRepo := fmt.Sprintf("%s/chisel/image-release", registryHost)
	beforeDefault := seedPinnedChiselImage(t, canonicalNativeChiselImage, defaultRepo+":fixture")
	beforeOverride := seedPinnedChiselImage(t, communityNativeChiselImage, overrideRepo+":fixture")

	configContent := strings.NewReplacer(
		"__DEFAULT_RELEASE_REPO__", defaultRepo,
		"__IMAGE_RELEASE_REPO__", overrideRepo,
		"__DEFAULT_CHISEL_RELEASE__", defaultChiselRelease,
	).Replace(chiselConfigTemplate)
	configPath := filepath.Join(t.TempDir(), "copa-bulk-chisel.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0o600))

	cmd := exec.Command(copaPath, "patch", "--config", configPath, "--debug", "--push", "--timeout=30m")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "bulk Chisel patch failed:\n%s", string(output))
	t.Logf("Copa command finished successfully. Output: %s", string(output))

	defaultOutputRef := defaultRepo + ":fixture-bulk-default"
	defaultOutput := readBulkChiselImage(t, defaultOutputRef)
	assertBulkChiselOutput(t, beforeDefault, defaultOutput, defaultChiselRelease)
	assertBulkChiselRuntime(t, defaultOutputRef)

	overrideOutput := readBulkChiselImage(t, overrideRepo+":fixture-bulk-override")
	assertBulkChiselOutput(t, beforeOverride, overrideOutput, imageChiselRelease)
}

func assertBulkChiselRuntime(t *testing.T, image string) {
	t.Helper()
	cmd := exec.Command("docker", "run", "--rm", "--network", "none", "--read-only", image, "--info") // #nosec G204 -- image is a test-owned local registry reference.
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "bulk-patched .NET runtime failed:\n%s", output)
	require.Contains(t, string(output), "Microsoft.NETCore.App")
}

func seedPinnedChiselImage(t *testing.T, source, destination string) bulkChiselImageState {
	t.Helper()

	sourceRef, err := name.ParseReference(source)
	require.NoError(t, err)
	image, err := remote.Image(sourceRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	require.NoError(t, err, "failed to pull pinned Chisel fixture %s", source)

	destinationRef, err := name.ParseReference(destination, name.Insecure)
	require.NoError(t, err)
	require.NoError(t, remote.Write(destinationRef, image), "failed to seed %s", destination)

	seededImage, err := remote.Image(destinationRef)
	require.NoError(t, err, "failed to read seeded Chisel fixture %s", destination)
	config, err := seededImage.ConfigFile()
	require.NoError(t, err)
	before := readChiselManifest(t, seededImage)
	require.NotEmpty(t, before.Packages, "source image %s has no Chisel packages", source)
	require.NotEmpty(t, before.Slices, "source image %s has no selected Chisel slices", source)
	return bulkChiselImageState{config: config, manifest: before}
}

func readBulkChiselImage(t *testing.T, imageRef string) bulkChiselImageState {
	t.Helper()

	ref, err := name.ParseReference(imageRef, name.Insecure)
	require.NoError(t, err)
	image, err := remote.Image(ref)
	require.NoError(t, err, "failed to pull bulk-patched image %s", imageRef)

	config, err := image.ConfigFile()
	require.NoError(t, err)

	rawManifest, err := image.RawManifest()
	require.NoError(t, err)
	var imageManifest struct {
		Annotations map[string]string `json:"annotations"`
	}
	require.NoError(t, json.Unmarshal(rawManifest, &imageManifest))

	rootFSPath := extractBulkChiselRootFS(t, image)
	manifest := readChiselManifestFromTar(t, rootFSPath)
	rootFSFile, err := os.Open(rootFSPath)
	require.NoError(t, err)
	verifyErr := chiselverify.VerifyTar(manifest, rootFSFile)
	closeErr := rootFSFile.Close()
	require.NoError(t, closeErr)
	require.NoErrorf(t, verifyErr, "flattened bulk image rootfs for %s does not match manifest.wall", imageRef)

	return bulkChiselImageState{
		config:              config,
		manifestAnnotations: imageManifest.Annotations,
		manifest:            manifest,
	}
}

func readChiselManifest(t *testing.T, image v1.Image) *copachisel.Manifest {
	t.Helper()

	rootFS := mutate.Extract(image)
	manifest, _ := readChiselManifestFromReader(t, rootFS)
	require.NoError(t, rootFS.Close())
	return manifest
}

func extractBulkChiselRootFS(t *testing.T, image v1.Image) string {
	t.Helper()

	rootFS := mutate.Extract(image)
	rootFSPath := filepath.Join(t.TempDir(), "rootfs.tar")
	rootFSFile, err := os.Create(rootFSPath)
	require.NoError(t, err)
	_, copyErr := io.Copy(rootFSFile, rootFS)
	fileCloseErr := rootFSFile.Close()
	rootFSCloseErr := rootFS.Close()
	require.NoError(t, copyErr, "failed to extract flattened image rootfs")
	require.NoError(t, fileCloseErr)
	require.NoError(t, rootFSCloseErr)
	return rootFSPath
}

func readChiselManifestFromTar(t *testing.T, rootFSPath string) *copachisel.Manifest {
	t.Helper()

	rootFSFile, err := os.Open(rootFSPath)
	require.NoError(t, err)
	manifest, _ := readChiselManifestFromReader(t, rootFSFile)
	require.NoError(t, rootFSFile.Close())
	return manifest
}

func readChiselManifestFromReader(t *testing.T, rootFS io.Reader) (*copachisel.Manifest, []byte) {
	t.Helper()

	reader := tar.NewReader(rootFS)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			t.Fatal("image does not contain /var/lib/chisel/manifest.wall")
		}
		require.NoError(t, err)
		if strings.TrimPrefix(filepath.ToSlash(header.Name), "./") != "var/lib/chisel/manifest.wall" {
			continue
		}

		data, err := io.ReadAll(reader)
		require.NoError(t, err)
		manifest, err := copachisel.ParseManifest(bytes.NewReader(data))
		require.NoError(t, err)
		return manifest, data
	}
}

func assertBulkChiselOutput(t *testing.T, before, after bulkChiselImageState, expectedRelease string) {
	t.Helper()

	require.NotNil(t, before.config)
	require.NotNil(t, after.config)
	require.NotNil(t, before.manifest)
	require.NotNil(t, after.manifest)
	require.NotEmpty(t, after.manifest.Packages)
	require.NotEmpty(t, after.manifest.Slices)
	assertBulkChiselConfigPreserved(t, before.config, after.config)

	beforeSlices := make(map[string]struct{}, len(before.manifest.Slices))
	for _, slice := range before.manifest.Slices {
		beforeSlices[slice] = struct{}{}
	}
	for slice := range beforeSlices {
		assert.Contains(t, after.manifest.Slices, slice, "bulk patch removed original Chisel slice %s", slice)
	}

	upgraded := 0
	for packageName, oldPackage := range before.manifest.Packages {
		newPackage, ok := after.manifest.Packages[packageName]
		require.True(t, ok, "bulk patch removed original Chisel package %s", packageName)
		comparison := compareBulkDebianVersions(t, newPackage.Version, oldPackage.Version)
		require.GreaterOrEqual(t, comparison, 0, "bulk patch downgraded Chisel package %s", packageName)
		if comparison > 0 {
			upgraded++
		}
	}
	require.Positive(t, upgraded, "bulk patch did not upgrade any native Chisel package")

	for packageName, pkg := range after.manifest.Packages {
		require.NotEmpty(t, pkg.Architecture, "package %s is missing its architecture", packageName)
		require.Len(t, pkg.SHA256, 64, "package %s is missing its archive digest", packageName)
	}

	for _, provenance := range []map[string]string{after.config.Config.Labels, after.manifestAnnotations} {
		require.Equal(t, expectedRelease, provenance[chiselReleaseAnnotation])
		require.Equal(t, expectedChiselVersion, provenance[chiselVersionAnnotation])
	}
}

func assertBulkChiselConfigPreserved(t *testing.T, before, after *v1.ConfigFile) {
	t.Helper()
	require.Equal(t, before.OS, after.OS)
	require.Equal(t, before.Architecture, after.Architecture)
	require.Equal(t, before.Config.User, after.Config.User)
	require.Equal(t, before.Config.Entrypoint, after.Config.Entrypoint)
	require.Equal(t, before.Config.Cmd, after.Config.Cmd)
	require.Equal(t, before.Config.Env, after.Config.Env)
	require.Equal(t, before.Config.WorkingDir, after.Config.WorkingDir)
	for key, value := range before.Config.Labels {
		require.Equalf(t, value, after.Config.Labels[key], "source image label %q changed", key)
	}
}

func compareBulkDebianVersions(t *testing.T, left, right string) int {
	t.Helper()

	leftVersion, err := debversion.NewVersion(left)
	require.NoError(t, err)
	rightVersion, err := debversion.NewVersion(right)
	require.NoError(t, err)
	switch {
	case leftVersion.LessThan(rightVersion):
		return -1
	case rightVersion.LessThan(leftVersion):
		return 1
	default:
		return 0
	}
}
