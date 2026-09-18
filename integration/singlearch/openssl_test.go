package integration

import (
	"archive/tar"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/distribution/reference"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/project-copacetic/copacetic/integration/common"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/stretchr/testify/require"
)

// TestPatchBuiltOpenSSL runs in both singlearch CI matrices. Its input is built
// from the checked-in recipe during this job, including for remote BuildKit.
func TestPatchBuiltOpenSSL(t *testing.T) {
	image := os.Getenv("COPA_TEST_OPENSSL_IMAGE")
	require.NotEmpty(t, image, "build the fixture with .github/workflows/scripts/singlearch-fixture.sh build, export its GITHUB_ENV entries, then run load after selecting the BuildKit backend")
	ref, err := reference.ParseNormalizedNamed(image)
	require.NoError(t, err)
	_, pinned := ref.(reference.Digested)
	require.True(t, pinned, "fixture input must include the digest produced by this job")
	require.True(t, strings.HasPrefix(reference.Domain(ref), "127.0.0.1:"), "fixture must come from the job's loopback registry")

	loader := imageloader.Docker
	if strings.HasPrefix(buildkitAddr, "podman-container://") {
		loader = imageloader.Podman
	}
	// Pull into the output loader as well, so the before/after checks inspect
	// the same manifest. Remote BuildKit still resolves it from the registry.
	pullArgs := []string{"pull", image}
	if loader == imageloader.Podman {
		pullArgs = append([]string{"pull", "--tls-verify=false"}, image)
	}
	openSSLCommand(t, loader, pullArgs...)
	if loader == imageloader.Podman {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, loader, "image", "rm", image) // #nosec G204 -- test-owned local-registry input.
			output, cleanupErr := cmd.CombinedOutput()
			require.NoError(t, cleanupErr, string(output))
		})
	}
	before, beforeConfig := inspectOpenSSLFixture(t, loader, image)

	dir := t.TempDir()
	ignoreFile := filepath.Join(dir, "ignore.rego")
	require.NoError(t, os.WriteFile(ignoreFile, common.TrivyIgnore, 0o600))
	cache := filepath.Join(dir, "trivy-cache")
	common.DownloadDBToDir(t, cache, common.DockerDINDAddress.Env()...)
	reportPath := filepath.Join(dir, "scan.json")
	common.NewScanner().WithIgnoreFile(ignoreFile).WithCacheDir(cache).
		WithSkipDBUpdate().WithPlatform("linux/amd64").WithOutput(reportPath).
		Scan(t, image, false, common.DockerDINDAddress.Env()...)
	reportBytes, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	var report trivyTypes.Report
	require.NoError(t, json.Unmarshal(reportBytes, &report))
	fixable := 0
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.PkgName == "libssl3" && vuln.FixedVersion != "" {
				fixable++
			}
		}
	}
	require.Positive(t, fixable, "the pinned fixture must still exercise an OpenSSL package update")
	t.Logf("fresh fixture %s has %d fixable libssl3 entries", image, fixable)

	patchedTag := "test-debian12-patched"
	patchedImage := reference.TrimNamed(ref).Name() + ":" + patchedTag
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, loader, "image", "rm", patchedImage) // #nosec G204 -- test-owned output.
		output, cleanupErr := cmd.CombinedOutput()
		require.NoError(t, cleanupErr, string(output))
	})
	args := []string{
		"patch", "--image", image, "--tag", patchedTag, "--addr", buildkitAddr,
		"--platform", "linux/amd64", "--timeout", "5m", "--progress", "plain",
	}
	if reportFile {
		args = append(args, "--report", reportPath, "--output", filepath.Join(dir, "vex.json"))
	}
	openSSLCommand(t, copaPath, args...)
	scanner := common.NewScanner().WithIgnoreFile(ignoreFile).WithCacheDir(cache).
		WithSkipDBUpdate().WithPlatform("linux/amd64").WithExitCode(1)
	if loader == imageloader.Podman {
		// Trivy's Podman source requires an API socket. Make the output loaded
		// by Copa available through this job's disposable registry as well.
		openSSLCommand(t, loader, "push", "--tls-verify=false", patchedImage)
		scanner.WithImageSrc("remote")
	}
	scanner.Scan(t, patchedImage, false, common.DockerDINDAddress.Env()...)
	after, afterConfig := inspectOpenSSLFixture(t, loader, patchedImage)
	require.Equal(t, before, after, "package status record names must be preserved")
	// Copa records the source reference as provenance; the remaining image
	// configuration must stay identical to the recipe's output.
	if beforeConfig.Labels == nil {
		beforeConfig.Labels = map[string]string{}
	}
	beforeConfig.Labels["BaseImage"] = image
	require.Equal(t, beforeConfig, afterConfig, "runtime image config must be preserved")
	if reportFile {
		common.ValidateVEXJSON(t, dir)
	}
}

func openSSLCommand(t *testing.T, program string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...) // #nosec G204 -- fixed test tools and fixture references.
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s %v:\n%s", program, args, output)
	return output
}

func inspectOpenSSLFixture(t *testing.T, loader, image string) (map[string]string, v1.Config) {
	t.Helper()
	var images []struct{ Config v1.Config }
	require.NoError(t, json.Unmarshal(openSSLCommand(t, loader, "image", "inspect", image), &images))
	require.Len(t, images, 1)
	id := strings.TrimSpace(string(openSSLCommand(t, loader, "create", image, "/not-executed")))
	defer openSSLCommand(t, loader, "rm", id)
	archive := filepath.Join(t.TempDir(), "rootfs.tar")
	openSSLCommand(t, loader, "export", "--output", archive, id)
	file, err := os.Open(archive)
	require.NoError(t, err)
	defer file.Close()
	reader := tar.NewReader(file)
	packages := map[string]string{}
	configFound := false
	for {
		header, readErr := reader.Next()
		if readErr == io.EOF {
			break
		}
		require.NoError(t, readErr)
		name := strings.TrimPrefix(header.Name, "./")
		require.NotEqual(t, "var/lib/dpkg/status", name, "full tooling database leaked")
		for _, prefix := range []string{"var/lib/apt/", "usr/bin/apt", "usr/bin/dpkg", "etc/debconf", "var/cache/debconf", "usr/share/debconf"} {
			require.False(t, strings.HasPrefix(name, prefix), "tooling state leaked: %s", name)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if name == "etc/ssl/openssl.cnf" {
			contents, readErr := io.ReadAll(reader)
			require.NoError(t, readErr)
			require.Equal(t, "foo\n", string(contents), "custom OpenSSL config replaced")
			configFound = true
		}
		if strings.HasPrefix(name, "var/lib/dpkg/status.d/") && !strings.HasSuffix(name, ".md5sums") {
			contents, readErr := io.ReadAll(reader)
			require.NoError(t, readErr)
			for _, line := range strings.Split(string(contents), "\n") {
				if packageName, ok := strings.CutPrefix(line, "Package: "); ok {
					packages[packageName] = name
				}
			}
		}
	}
	require.True(t, configFound, "missing custom OpenSSL configuration")
	require.Len(t, packages, 5, "pinned Distroless package inventory changed")
	require.Contains(t, packages, "libssl3")
	return packages, images[0].Config
}
