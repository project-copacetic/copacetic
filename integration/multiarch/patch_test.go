package integration

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/integration/common"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed fixtures/test-images.json
var testImages []byte

const lastPatchedAnnotation = "sh.copa.image.patched"

type testImage struct {
	OriginalImage   string   `json:"originalImage"`
	LocalImage      string   `json:"localImage"`
	Push            bool     `json:"push"`
	Tag             string   `json:"tag"`
	Distro          string   `json:"distro"`
	Description     string   `json:"description"`
	IgnoreErrors    bool     `json:"ignoreErrors"`
	SkipAnnotations bool     `json:"skipAnnotations,omitempty"`
	Platforms       []string `json:"platforms"`
}

func TestPatch(t *testing.T) {
	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	tmp := t.TempDir()
	ignoreFile := filepath.Join(tmp, "ignore.rego")
	err = os.WriteFile(ignoreFile, common.TrivyIgnore, 0o600)
	require.NoError(t, err)

	// download the trivy db before running the tests
	common.DownloadDB(t, common.DockerDINDAddress.Env()...)

	for _, img := range images {
		t.Run(img.Description, func(t *testing.T) {
			// define a few variables
			ref := fmt.Sprintf("%s:%s", img.LocalImage, img.Tag)
			originalImageRef := fmt.Sprintf("%s:%s", img.OriginalImage, img.Tag)

			// copy over the original image to the local image using oras
			copyImage(t, originalImageRef, ref)

			reportDir := t.TempDir()

			t.Log("creating scan reports for each platform")
			var wg sync.WaitGroup
			for _, platformStr := range img.Platforms {
				wg.Add(1)
				go func() {
					defer wg.Done()

					suffix := strings.ReplaceAll(platformStr, "/", "-")
					reportPath := filepath.Join(reportDir, "report-"+suffix+".json")

					t.Logf("scanning original image for platform %s", platformStr)
					common.NewScanner().
						WithIgnoreFile(ignoreFile).
						WithOutput(reportPath).
						WithSkipDBUpdate().
						WithPlatform(platformStr).
						// Do not set a non-zero exit code because we are expecting vulnerabilities.
						Scan(t, ref, img.IgnoreErrors, common.DockerDINDAddress.Env()...)
				}()
			}
			wg.Wait()

			tagPatched := img.Tag + "-patched"
			patchedRef := fmt.Sprintf("%s:%s", img.LocalImage, tagPatched)

			t.Log("patching image with multiple architectures")
			patchMultiPlatform(t, ref, tagPatched, reportDir, img.IgnoreErrors, img.Push)

			if img.Push && !img.SkipAnnotations {
				t.Log("verifying OCI annotations are preserved")
				verifyAnnotations(t, patchedRef, img.Platforms, reportDir)
			}

			t.Log("scanning patched image for each platform")
			wg = sync.WaitGroup{}
			for _, platformStr := range img.Platforms {
				wg.Add(1)
				go func() {
					defer wg.Done()
					// only want the platform string for the scanner
					parts := strings.Split(platformStr, "/")
					archStr := strings.Split(platformStr, "/")[1]
					patchedArchRef := fmt.Sprintf("%s-%s", patchedRef, archStr)
					if len(parts) > 2 {
						variantStr := strings.Split(platformStr, "/")[2]
						patchedArchRef += "-" + variantStr
					}

					// run the image so the layers are fully loaded. a manifest-only load/push
					// leaves the tag without its layer blobs; running "true" forces the daemon
					// to pull/unpack the layers, then exits instantly. Without this, the
					// subsequent Trivy scan can hit “snapshot … does not exist”.
					cmd := exec.Command("docker", "run", "--rm", patchedArchRef, "true")
					out, err := cmd.CombinedOutput()
					require.NoError(t, err, string(out))

					t.Logf("scanning patched image for platform %s", platformStr)
					common.NewScanner().
						WithIgnoreFile(ignoreFile).
						WithSkipDBUpdate().
						WithImageSrc("docker").
						WithPlatform(platformStr).
						// here we want a non-zero exit code because we are expecting no vulnerabilities.
						WithExitCode(1).
						Scan(t, patchedArchRef, img.IgnoreErrors, common.DockerDINDAddress.Env()...)
				}()
			}
			wg.Wait()
		})
	}
}

// Tests patching only some architectures while preserving others.
func TestPatchPartialArchitectures(t *testing.T) {
	// Test image with multiple platforms including Windows
	originalImage := "registry.k8s.io/csi-secrets-store/driver"
	tag := "v1.4.8"
	localImage := "localhost:5000/secrets-store-test"

	originalRef := fmt.Sprintf("%s:%s", originalImage, tag)
	localRef := fmt.Sprintf("%s:%s", localImage, tag)

	// Copy the original multi-arch image to local registry
	copyImage(t, originalRef, localRef)

	// Create a temporary directory for reports
	reportDir := t.TempDir()

	// Only scan amd64 platform
	platformToScan := "linux/amd64"
	suffix := strings.ReplaceAll(platformToScan, "/", "-")
	reportPath := filepath.Join(reportDir, "report-"+suffix+".json")

	t.Logf("scanning original image for platform %s only", platformToScan)
	common.NewScanner().
		WithOutput(reportPath).
		WithSkipDBUpdate().
		WithPlatform(platformToScan).
		Scan(t, localRef, false)

	// Patch the image
	patchedTag := tag + "-partial-patched"
	patchedRef := fmt.Sprintf("%s:%s", localImage, patchedTag)

	t.Log("patching image with only linux/amd64 platform report")
	patchMultiPlatform(t, localRef, patchedTag, reportDir, false, true)

	// Verify the patched manifest still contains all original platforms
	t.Log("verifying manifest contains all original platforms")

	// Get original manifest platforms
	originalPlatforms := getManifestPlatforms(t, originalRef)
	t.Logf("original platforms: %v", originalPlatforms)

	// Get patched manifest platforms
	patchedPlatforms := getManifestPlatforms(t, patchedRef)
	t.Logf("patched platforms: %v", patchedPlatforms)

	// Verify all original platforms are preserved
	require.Equal(t, len(originalPlatforms), len(patchedPlatforms),
		"patched manifest should have same number of platforms as original")

	// Count expected platforms from original manifest
	expectedLinuxCount := 0
	expectedWindowsCount := 0
	for _, p := range originalPlatforms {
		switch p.OS {
		case "linux":
			expectedLinuxCount++
		case "windows":
			expectedWindowsCount++
		}
	}

	// Verify we have the expected number of Linux and Windows platforms
	actualLinuxCount := 0
	actualWindowsCount := 0
	for _, p := range patchedPlatforms {
		switch p.OS {
		case "linux":
			actualLinuxCount++
		case "windows":
			actualWindowsCount++
		}
	}

	require.Equal(t, expectedLinuxCount, actualLinuxCount, "should contain %d Linux platforms", expectedLinuxCount)
	require.Equal(t, expectedWindowsCount, actualWindowsCount, "should contain %d Windows platforms", expectedWindowsCount)

	// Verify that all original platforms are preserved in the patched manifest
	for _, originalPlatform := range originalPlatforms {
		found := false
		for _, patchedPlatform := range patchedPlatforms {
			if originalPlatform.OS == patchedPlatform.OS &&
				originalPlatform.Architecture == patchedPlatform.Architecture &&
				originalPlatform.Variant == patchedPlatform.Variant &&
				originalPlatform.OSVersion == patchedPlatform.OSVersion {
				found = true
				break
			}
		}
		require.True(t, found, "original platform %s/%s (variant: %s, osversion: %s) should be preserved",
			originalPlatform.OS, originalPlatform.Architecture, originalPlatform.Variant, originalPlatform.OSVersion)
	}
}

// getManifestPlatforms extracts platform information from a manifest.
func getManifestPlatforms(t *testing.T, imageRef string) []Platform {
	// For localhost registry, use registry API since docker manifest inspect
	// doesn't work well with local insecure registries
	if strings.HasPrefix(imageRef, "localhost:5000/") {
		return getManifestPlatformsFromRegistry(t, imageRef)
	}

	// For external registries, use docker manifest inspect
	cmd := exec.Command("docker", "manifest", "inspect", imageRef)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to inspect manifest: %s", string(output))

	var manifest struct {
		Manifests []struct {
			Platform Platform `json:"platform"`
		} `json:"manifests"`
	}

	err = json.Unmarshal(output, &manifest)
	require.NoError(t, err, "failed to parse manifest JSON")

	platforms := make([]Platform, len(manifest.Manifests))
	for i, m := range manifest.Manifests {
		platforms[i] = m.Platform
	}

	return platforms
}

// Gets platform info directly from registry API.
func getManifestPlatformsFromRegistry(t *testing.T, imageRef string) []Platform {
	// Parse image reference: localhost:5000/repo:tag
	parts := strings.SplitN(imageRef, "/", 2)
	require.Len(t, parts, 2, "invalid image reference format")

	repoParts := strings.SplitN(parts[1], ":", 2)
	repo := repoParts[0]
	tag := "latest"
	if len(repoParts) == 2 {
		tag = repoParts[1]
	}

	// Get manifest from registry
	url := fmt.Sprintf("http://localhost:5000/v2/%s/manifests/%s", repo, tag)
	cmd := exec.Command("curl", "-s", "-H", "Accept: application/vnd.docker.distribution.manifest.list.v2+json", url)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to get manifest from registry: %s", string(output))

	var manifest struct {
		Manifests []struct {
			Platform Platform `json:"platform"`
		} `json:"manifests"`
	}

	err = json.Unmarshal(output, &manifest)
	require.NoError(t, err, "failed to parse manifest JSON: %s", string(output))

	platforms := make([]Platform, len(manifest.Manifests))
	for i, m := range manifest.Manifests {
		platforms[i] = m.Platform
	}

	return platforms
}

// Platform represents a platform in a manifest.
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	OSVersion    string `json:"os.version,omitempty"`
	Variant      string `json:"variant,omitempty"`
}

func patchMultiPlatform(t *testing.T, ref, patchedTag, reportDir string, ignoreErrors, push bool) {
	var addrFl string
	if buildkitAddr != "" {
		addrFl = "-a=" + buildkitAddr
	}

	args := []string{
		"patch",
		"-i=" + ref,
		"-t=" + patchedTag,
		"--report=" + reportDir,
		"-s=" + scannerPlugin,
		"--timeout=30m",
		addrFl,
		"--ignore-errors=" + strconv.FormatBool(ignoreErrors),
		"--debug",
	}
	if push {
		args = append(args, "--push")
	}

	//#nosec G204
	cmd := exec.Command(
		copaPath,
		args...,
	)

	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, common.DockerDINDAddress.Env()...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v", err)
	}
}

// helper to copy an image using oras.
func copyImage(t *testing.T, src, dst string) {
	cmd := exec.Command(
		"oras",
		"copy",
		src,
		dst,
	)
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, common.DockerDINDAddress.Env()...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

// ManifestData represents the JSON structure returned by docker buildx imagetools inspect.
type ManifestData struct {
	Annotations map[string]string `json:"annotations"`
	Manifests   []ManifestEntry   `json:"manifests"`
}

type ManifestEntry struct {
	Platform    PlatformInfo      `json:"platform"`
	Annotations map[string]string `json:"annotations"`
}

type PlatformInfo struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

// verifyAnnotations checks that Copa properly preserves OCI annotations.
// This function verifies:
// 1. Index-level annotations: Copa metadata (copacetic.patched, timestamps)
// 2. Manifest-level annotations: Original platform-specific annotations are preserved
// 3. Updated timestamps: Patched platforms get updated creation timestamps.
func verifyAnnotations(t *testing.T, patchedRef string, platforms []string, reportDir string) {
	t.Log("checking index-level annotations")

	// Get the raw manifest using docker buildx imagetools
	cmd := exec.Command("docker", "buildx", "imagetools", "inspect", patchedRef, "--raw")
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, common.DockerDINDAddress.Env()...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to inspect patched image: %s", string(out))

	var manifest ManifestData
	err = json.Unmarshal(out, &manifest)
	require.NoError(t, err, "failed to parse manifest JSON")

	// Check index-level annotations
	assert.NotEmpty(t, manifest.Annotations, "index-level annotations should not be empty")
	assert.NotEmpty(t, manifest.Annotations["org.opencontainers.image.created"], "should have created annotation")

	t.Logf("found %d index-level annotations", len(manifest.Annotations))

	// Check manifest-level annotations for each platform
	t.Log("checking manifest-level annotations for patched platforms")

	for _, manifestEntry := range manifest.Manifests {
		platformStr := formatPlatform(manifestEntry.Platform)

		// Only check platforms that actually have vulnerability reports (were patched)
		if isPatchablePlatform(platformStr, platforms, reportDir) {
			t.Logf("checking manifest annotations for patched platform %s", platformStr)

			// The created timestamp should be updated for patched platforms
			if createdTime, exists := manifestEntry.Annotations["org.opencontainers.image.created"]; exists {
				assert.NotEmpty(t, createdTime, "created timestamp should not be empty for patched platform %s", platformStr)
				t.Logf("platform %s has updated created timestamp: %s", platformStr, createdTime)
			}

			// Check for Copa image.patched annotation on patched platforms
			lastPatched, exists := manifestEntry.Annotations[lastPatchedAnnotation]
			assert.True(t, exists, "patched platform %s should have %s annotation", platformStr, lastPatchedAnnotation)
			assert.NotEmpty(t, lastPatched, "%s timestamp should not be empty for patched platform %s", lastPatchedAnnotation, platformStr)
			t.Logf("platform %s has %s timestamp: %s", platformStr, lastPatchedAnnotation, lastPatched)

			t.Logf("platform %s has %d manifest-level annotations", platformStr, len(manifestEntry.Annotations))

			// Verify that ALL original annotations are preserved
			// Get the original image reference
			originalRef := strings.Replace(patchedRef, "-patched", "", 1)

			// Get original platform annotations
			// Create platform object from manifestEntry
			platform := &ocispec.Platform{
				OS:           manifestEntry.Platform.OS,
				Architecture: manifestEntry.Platform.Architecture,
				Variant:      manifestEntry.Platform.Variant,
			}
			originalAnnotations, err := utils.GetPlatformManifestAnnotations(context.Background(), originalRef, platform)
			require.NoError(t, err, "failed to get original annotations for platform %s", platformStr)

			// Check that every original annotation is present in the patched manifest
			// Some annotations are expected to change during patching
			annotationsThatChange := map[string]bool{
				"org.opencontainers.image.created": true,
				"org.opencontainers.image.version": true,
			}

			for key, originalValue := range originalAnnotations {
				patchedValue, exists := manifestEntry.Annotations[key]
				assert.True(t, exists, "original annotation %s is missing in patched manifest for platform %s", key, platformStr)

				if exists && !annotationsThatChange[key] {
					// For annotations that shouldn't change, verify the values are equal
					assert.Equal(t, originalValue, patchedValue, "annotation %s value changed for platform %s: original=%s, patched=%s", key, platformStr, originalValue, patchedValue)
				}
			}

			t.Logf("verified %d original annotations are preserved for platform %s", len(originalAnnotations), platformStr)
		} else {
			t.Logf("checking platform %s (no vulnerability report, not patched)", platformStr)

			// Non-patched platforms should NOT have the Copa image.patched annotation
			_, exists := manifestEntry.Annotations[lastPatchedAnnotation]
			assert.False(t, exists, "non-patched platform %s should not have %s annotation", platformStr, lastPatchedAnnotation)
		}
	}
}

// formatPlatform creates a platform string from PlatformInfo.
func formatPlatform(p PlatformInfo) string {
	platform := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		platform += "/" + p.Variant
	}
	return platform
}

// isPatchablePlatform checks if a platform actually has a vulnerability report file
// and therefore should have been patched by Copa.
func isPatchablePlatform(platform string, allPlatforms []string, reportDir string) bool {
	// First verify this platform is in the test's platform list
	found := false
	for _, testPlatform := range allPlatforms {
		if testPlatform == platform {
			found = true
			break
		}
	}
	if !found {
		return false
	}

	// Check if a vulnerability report exists for this platform
	// Report files are named like "report-linux-amd64.json"
	suffix := strings.ReplaceAll(platform, "/", "-")
	reportPath := filepath.Join(reportDir, "report-"+suffix+".json")

	// Check if the report file exists and is not empty
	if info, err := os.Stat(reportPath); err == nil && info.Size() > 0 {
		// A non-empty vulnerability report exists, so this platform should be patched
		return true
	}

	// No vulnerability report or empty report means platform was not patched
	return false
}
