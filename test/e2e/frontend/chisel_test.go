package frontend

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	debversion "github.com/knqyf263/go-deb-version"
	"github.com/project-copacetic/copacetic/internal/testutil/chiselverify"
	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"
	"github.com/stretchr/testify/require"
)

const (
	frontendNativeChiselImage = "docker.io/ubuntu/dotnet-runtime:8.0-24.04_stable_145@sha256:20bd739a82b977ad1fc882d0a73be15df8db4ad04c9cee210ba2572fdc273351"
	frontendChiselRelease     = "ubuntu-24.04"
	frontendChiselVersion     = "v1.4.2"

	frontendChiselReleaseRepository = "https://github.com/canonical/chisel-releases.git"
	frontendChiselReleaseCommit     = "ca7ad8113998470ff77231af799c363c4a48feca"

	frontendChiselReleaseAnnotation = "sh.copa.chisel.release"
	frontendChiselVersionAnnotation = "sh.copa.chisel.version"

	buildctlAddressFlag          = "--addr"
	buildctlFrontendOpt          = "--frontend=gateway.v0"
	buildxAddress                = "buildx://"
	frontendChiselBuildAttempts  = 3
	frontendChiselRetryBaseDelay = 5 * time.Second
)

type frontendChiselSnapshot struct {
	Config              frontendChiselImageInspect
	Manifest            *copachisel.Manifest
	ManifestData        []byte
	OCIManifestData     []byte
	ManifestAnnotations map[string]string
}

type frontendChiselImageInspect struct {
	Architecture string `json:"Architecture"`
	OS           string `json:"Os"`
	Config       struct {
		User       string            `json:"User"`
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
		Env        []string          `json:"Env"`
		WorkingDir string            `json:"WorkingDir"`
		Labels     map[string]string `json:"Labels"`
	} `json:"Config"`
}

type frontendOCIManifest struct {
	Annotations map[string]string `json:"annotations"`
}

func runFrontendNamedChiselTest(t *testing.T) {
	baseline := "localhost:5000/frontend-chisel:baseline-named"
	patched := "localhost:5000/frontend-chisel:patched-named"
	repatched := "localhost:5000/frontend-chisel:repatched-named"
	copyFrontendChiselFixture(t, baseline)

	before := captureFrontendChiselImage(t, baseline)
	buildkitAddress := frontendBuildkitAddress(t)
	runFrontendChiselBuild(t, buildkitAddress, baseline, patched, frontendChiselRelease, "")

	after := captureFrontendChiselImage(t, patched)
	assertFrontendChiselRuntimeConfigPreserved(t, &before.Config, &after.Config)
	assertFrontendChiselUpgrade(t, before.Manifest, after.Manifest)
	assertFrontendChiselProvenance(t, &after, frontendChiselRelease)

	// A second comprehensive run must succeed as an idempotent frontend build,
	// retain the supplied image state, and preserve both config labels and OCI
	// manifest annotations.
	runFrontendChiselBuild(t, buildkitAddress, patched, repatched, frontendChiselRelease, "")
	repatch := captureFrontendChiselImage(t, repatched)
	assertFrontendChiselRuntimeConfigPreserved(t, &after.Config, &repatch.Config)
	require.Equal(t, after.Config.Config.Labels, repatch.Config.Config.Labels)
	require.Equal(t, after.ManifestData, repatch.ManifestData, "no-update frontend export changed manifest.wall")
	require.Equal(t, after.OCIManifestData, repatch.OCIManifestData, "no-update frontend export changed the OCI manifest")
	assertFrontendChiselProvenance(t, &repatch, frontendChiselRelease)
}

func runFrontendLocalChiselReleaseTest(t *testing.T) {
	baseline := "localhost:5000/frontend-chisel:baseline-local"
	patched := "localhost:5000/frontend-chisel:patched-local"
	copyFrontendChiselFixture(t, baseline)

	releaseDirectory := checkoutFrontendChiselRelease(t)
	before := captureFrontendChiselImage(t, baseline)
	runFrontendChiselBuild(t, frontendBuildkitAddress(t), baseline, patched, ".", releaseDirectory)

	after := captureFrontendChiselImage(t, patched)
	assertFrontendChiselRuntimeConfigPreserved(t, &before.Config, &after.Config)
	assertFrontendChiselUpgrade(t, before.Manifest, after.Manifest)

	releaseProvenance := after.Config.Config.Labels[frontendChiselReleaseAnnotation]
	assertLocalFrontendChiselProvenance(t, releaseProvenance)
	assertFrontendChiselProvenance(t, &after, releaseProvenance)
}

func copyFrontendChiselFixture(t *testing.T, destination string) {
	t.Helper()
	output := runFrontendChiselCommand(t, "oras", "cp", "--platform", "linux/amd64", "--to-plain-http", frontendNativeChiselImage, destination)
	t.Logf("Copied pinned native Chisel fixture to %s:\n%s", destination, output)
	t.Cleanup(func() { removeLocalImage(t, destination) })
}

func runFrontendChiselBuild(t *testing.T, buildkitAddress, input, output, release, releaseDirectory string) string {
	t.Helper()
	inputForBuildkit := frontendRegistryReference(input)
	outputForBuildkit := frontendRegistryReference(output)

	args := []string{
		buildctlAddressFlag, buildkitAddress,
		buildCommand,
		buildctlFrontendOpt,
		buildctlOptionFlag, fmt.Sprintf("source=%s", frontendImage),
		buildctlOptionFlag, fmt.Sprintf("image=%s", inputForBuildkit),
		buildctlOptionFlag, fmt.Sprintf("chisel-release=%s", release),
		buildctlOptionFlag, "platform=linux/amd64",
		outputFlag, fmt.Sprintf("type=image,name=%s,push=true,oci-mediatypes=true", outputForBuildkit),
		"--progress", "plain",
		"--allow", "security.insecure",
	}
	if releaseDirectory != "" {
		args = append(args,
			"--local", fmt.Sprintf("chisel-release=%s", releaseDirectory),
			buildctlOptionFlag, "context:chisel-release=local:chisel-release",
		)
	}

	var outputText string
	for attempt := 1; attempt <= frontendChiselBuildAttempts; attempt++ {
		cmd := exec.Command("buildctl", args...) // #nosec G204 -- arguments use fixed fixtures and test-owned references.
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		commandOutput, err := cmd.CombinedOutput()
		outputText = string(commandOutput)
		if err == nil {
			break
		}
		if attempt == frontendChiselBuildAttempts || !isTransientFrontendChiselBuildFailure(outputText) {
			require.NoErrorf(t, err, "buildctl %s failed:\n%s", strings.Join(args, " "), outputText)
		}

		delay := time.Duration(attempt) * frontendChiselRetryBaseDelay
		t.Logf("Transient Chisel archive failure on attempt %d/%d; retrying in %s:\n%s", attempt, frontendChiselBuildAttempts, delay, outputText)
		time.Sleep(delay)
	}

	t.Logf("Frontend Chisel build %s -> %s completed:\n%s", input, output, outputText)
	t.Cleanup(func() { removeLocalImage(t, output) })
	return outputText
}

func isTransientFrontendChiselBuildFailure(output string) bool {
	lowerOutput := strings.ToLower(output)
	for _, marker := range []string{
		"cannot talk to archive",
		"client.timeout exceeded while awaiting headers",
		"connection reset by peer",
		"context deadline exceeded",
		"i/o timeout",
		"temporary failure in name resolution",
		"tls handshake timeout",
		"unexpected eof",
	} {
		if strings.Contains(lowerOutput, marker) {
			return true
		}
	}
	return false
}

func TestIsTransientFrontendChiselBuildFailure(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{name: "archive timeout", output: `error: cannot talk to archive: context deadline exceeded`, want: true},
		{name: "header timeout", output: `Client.Timeout exceeded while awaiting headers`, want: true},
		{name: "connection reset", output: `read: connection reset by peer`, want: true},
		{name: "deterministic slice error", output: `slice foo_bar does not exist`, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, isTransientFrontendChiselBuildFailure(tt.output))
		})
	}
}

func frontendBuildkitAddress(t *testing.T) string {
	t.Helper()
	if buildkitAddr != buildxAddress {
		return buildkitAddr
	}
	address := ensureBuildxBuilder(t)
	t.Logf("buildx:// not supported by this buildctl version, using %s", address)
	return address
}

func frontendRegistryReference(reference string) string {
	bridgeGateway := os.Getenv("DOCKER_BRIDGE_GATEWAY")
	if bridgeGateway == "" {
		bridgeGateway = defaultBridgeGateway
	}
	return strings.Replace(reference, "localhost:5000", fmt.Sprintf("%s:5000", bridgeGateway), 1)
}

func checkoutFrontendChiselRelease(t *testing.T) string {
	t.Helper()
	releaseDirectory := filepath.Join(t.TempDir(), "release")
	runFrontendChiselCommand(t, "git", "init", "--quiet", releaseDirectory)
	runFrontendChiselCommand(t, "git", "-C", releaseDirectory, "remote", "add", "origin", frontendChiselReleaseRepository)
	runFrontendChiselCommand(t, "git", "-c", "credential.helper=", "-C", releaseDirectory,
		"fetch", "--depth=1", "origin", frontendChiselReleaseCommit)
	runFrontendChiselCommand(t, "git", "-C", releaseDirectory, "checkout", "--quiet", "--detach", "FETCH_HEAD")
	resolved := strings.TrimSpace(runFrontendChiselCommand(t, "git", "-C", releaseDirectory, "rev-parse", "HEAD"))
	require.Equal(t, frontendChiselReleaseCommit, resolved, "local Chisel release checkout did not resolve to the pinned commit")
	require.NoError(t, os.RemoveAll(filepath.Join(releaseDirectory, ".git")))
	return releaseDirectory
}

func captureFrontendChiselImage(t *testing.T, image string) frontendChiselSnapshot {
	t.Helper()
	runFrontendChiselCommand(t, "docker", "pull", "--platform", "linux/amd64", image)

	inspectData := []byte(runFrontendChiselCommand(t, "docker", "image", "inspect", image))
	var configs []frontendChiselImageInspect
	require.NoError(t, json.Unmarshal(inspectData, &configs))
	require.Len(t, configs, 1)

	containerID := strings.TrimSpace(runFrontendChiselCommand(t, "docker", "create", "--platform", "linux/amd64", image))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "--force", containerID).Run()
	})
	exportDirectory := t.TempDir()
	manifestPath := filepath.Join(exportDirectory, "manifest.wall")
	rootFSPath := filepath.Join(exportDirectory, "rootfs.tar")
	runFrontendChiselCommand(t, "docker", "cp", containerID+":/var/lib/chisel/manifest.wall", manifestPath)
	runFrontendChiselCommand(t, "docker", "export", "--output", rootFSPath, containerID)
	runFrontendChiselCommand(t, "docker", "rm", containerID)
	manifestData, err := os.ReadFile(manifestPath)
	require.NoError(t, err)
	manifest, err := copachisel.ParseManifest(bytes.NewReader(manifestData))
	require.NoError(t, err)
	require.NotEmpty(t, manifest.Packages)
	require.NotEmpty(t, manifest.Slices)
	rootFS, err := os.Open(rootFSPath)
	require.NoError(t, err)
	verifyErr := chiselverify.VerifyTar(manifest, rootFS)
	closeErr := rootFS.Close()
	require.NoError(t, closeErr)
	require.NoErrorf(t, verifyErr, "Docker-exported rootfs for %s does not match manifest.wall", image)

	ociManifestData := []byte(runFrontendChiselCommand(t, "oras", "manifest", "fetch", "--plain-http", "--platform", "linux/amd64", image))
	var ociManifest frontendOCIManifest
	require.NoError(t, json.Unmarshal(ociManifestData, &ociManifest))

	return frontendChiselSnapshot{
		Config:              configs[0],
		Manifest:            manifest,
		ManifestData:        manifestData,
		OCIManifestData:     ociManifestData,
		ManifestAnnotations: ociManifest.Annotations,
	}
}

func assertFrontendChiselRuntimeConfigPreserved(t *testing.T, before, after *frontendChiselImageInspect) {
	t.Helper()
	require.Equal(t, before.Architecture, after.Architecture)
	require.Equal(t, before.OS, after.OS)
	require.Equal(t, before.Config.User, after.Config.User)
	require.Equal(t, before.Config.Entrypoint, after.Config.Entrypoint)
	require.Equal(t, before.Config.Cmd, after.Config.Cmd)
	require.Equal(t, before.Config.Env, after.Config.Env)
	require.Equal(t, before.Config.WorkingDir, after.Config.WorkingDir)
	for key, value := range before.Config.Labels {
		require.Equalf(t, value, after.Config.Labels[key], "source image label %q changed", key)
	}
}

func assertFrontendChiselUpgrade(t *testing.T, before, after *copachisel.Manifest) {
	t.Helper()
	beforeSlices := make(map[string]struct{}, len(before.Slices))
	for _, slice := range before.Slices {
		beforeSlices[slice] = struct{}{}
	}
	afterSlices := make(map[string]struct{}, len(after.Slices))
	for _, slice := range after.Slices {
		afterSlices[slice] = struct{}{}
	}
	for slice := range beforeSlices {
		_, ok := afterSlices[slice]
		require.Truef(t, ok, "frontend Chisel patch dropped original slice %q", slice)
	}

	upgraded := 0
	for name, beforePackage := range before.Packages {
		afterPackage, ok := after.Packages[name]
		require.Truef(t, ok, "frontend Chisel patch dropped original package %q", name)
		beforeVersion, err := debversion.NewVersion(beforePackage.Version)
		require.NoErrorf(t, err, "invalid original Debian version for %s", name)
		afterVersion, err := debversion.NewVersion(afterPackage.Version)
		require.NoErrorf(t, err, "invalid patched Debian version for %s", name)
		comparison := afterVersion.Compare(beforeVersion)
		require.GreaterOrEqualf(t, comparison, 0, "frontend Chisel patch downgraded package %s", name)
		if comparison > 0 {
			upgraded++
		}
	}
	require.Positive(t, upgraded, "frontend Chisel patch did not upgrade any package")
}

func assertFrontendChiselProvenance(t *testing.T, snapshot *frontendChiselSnapshot, expectedRelease string) {
	t.Helper()
	require.Equal(t, expectedRelease, snapshot.Config.Config.Labels[frontendChiselReleaseAnnotation])
	require.Equal(t, frontendChiselVersion, snapshot.Config.Config.Labels[frontendChiselVersionAnnotation])
	require.Equal(t, expectedRelease, snapshot.ManifestAnnotations[frontendChiselReleaseAnnotation])
	require.Equal(t, frontendChiselVersion, snapshot.ManifestAnnotations[frontendChiselVersionAnnotation])
}

func assertLocalFrontendChiselProvenance(t *testing.T, provenance string) {
	t.Helper()
	const prefix = "local:copa-frontend-chisel-release-"
	require.Truef(t, strings.HasPrefix(provenance, prefix), "unexpected local Chisel provenance %q", provenance)
	parts := strings.SplitN(provenance, "@sha256:", 2)
	require.Len(t, parts, 2)
	require.NotEmpty(t, strings.TrimPrefix(parts[0], "local:"))
	require.Len(t, parts[1], 64)
	_, err := hex.DecodeString(parts[1])
	require.NoError(t, err, "local Chisel provenance digest is not hexadecimal")
}

func runFrontendChiselCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...) // #nosec G204 -- commands use fixed test fixtures and test-owned temporary paths.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	require.NoErrorf(t, err, "%s %s failed:\n%s", name, strings.Join(args, " "), stderr.String())
	if stderr.Len() > 0 {
		t.Logf("%s stderr:\n%s", name, stderr.String())
	}
	return stdout.String()
}
