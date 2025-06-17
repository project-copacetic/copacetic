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
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	//go:embed fixtures/test-images.json
	testImages []byte

	//go:embed fixtures/trivy_ignore.rego
	trivyIgnore []byte
)

type testImage struct {
	OriginalImage string   `json:"originalImage"`
	LocalImage    string   `json:"localImage"`
	Push          bool     `json:"push"`
	Tag           string   `json:"tag"`
	Distro        string   `json:"distro"`
	Description   string   `json:"description"`
	IgnoreErrors  bool     `json:"ignoreErrors"`
	Platforms     []string `json:"platforms"`
}

func TestPatch(t *testing.T) {
	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	tmp := t.TempDir()
	ignoreFile := filepath.Join(tmp, "ignore.rego")
	err = os.WriteFile(ignoreFile, trivyIgnore, 0o600)
	require.NoError(t, err)

	// download the trivy db before running the tests
	downloadDB(t)

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
					scanner().
						withIgnoreFile(ignoreFile).
						withOutput(reportPath).
						withSkipDBUpdate().
						withPlatform(platformStr).
						// Do not set a non-zero exit code because we are expecting vulnerabilities.
						scan(t, ref, img.IgnoreErrors)
				}()
			}
			wg.Wait()

			tagPatched := img.Tag + "-patched"
			patchedRef := fmt.Sprintf("%s:%s", img.LocalImage, tagPatched)

			t.Log("patching image with multiple architectures")
			patchMultiPlatform(t, ref, tagPatched, reportDir, img.IgnoreErrors, img.Push)

			if img.Push {
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
					scanner().
						withIgnoreFile(ignoreFile).
						withSkipDBUpdate().
						withImageSrc("docker").
						withPlatform(platformStr).
						// here we want a non-zero exit code because we are expecting no vulnerabilities.
						withExitCode(1).
						scan(t, patchedArchRef, img.IgnoreErrors)
				}()
			}
			wg.Wait()
		})
	}
}

type addrWrapper struct {
	m       sync.Mutex
	address *string
}

var dockerDINDAddress addrWrapper

func (w *addrWrapper) addr() string {
	w.m.Lock()
	defer w.m.Unlock()

	if w.address != nil {
		return *w.address
	}

	w.address = new(string)
	if addr := os.Getenv("COPA_BUILDKIT_ADDR"); addr != "" && strings.HasPrefix(addr, "docker://") {
		*w.address = strings.TrimPrefix(addr, "docker://")
	}

	return *w.address
}

func (w *addrWrapper) env() []string {
	a := dockerDINDAddress.addr()
	if a == "" {
		return []string{}
	}

	return []string{fmt.Sprintf("DOCKER_HOST=%s", a)}
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
	cmd.Env = append(cmd.Env, dockerDINDAddress.env()...)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v", err)
	}
}

func scanner() *scannerCmd {
	return &scannerCmd{}
}

type scannerCmd struct {
	output       string
	skipDBUpdate bool
	ignoreFile   string
	exitCode     int
	platform     string
	imageSrc     string
}

func downloadDB(t *testing.T) {
	args := []string{
		"trivy",
		"image",
		"--download-db-only",
		"--db-repository=ghcr.io/aquasecurity/trivy-db:2,public.ecr.aws/aquasecurity/trivy-db",
	}
	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, dockerDINDAddress.env()...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

func (s *scannerCmd) scan(t *testing.T, ref string, ignoreErrors bool) {
	args := []string{
		"trivy",
		"image",
		"--quiet",
		"--pkg-types=os",
		"--ignore-unfixed",
		"--scanners=vuln",
	}
	if s.output != "" {
		args = append(args, []string{"-o=" + s.output, "-f=json"}...)
	}
	if s.skipDBUpdate {
		args = append(args, "--skip-db-update")
	}
	if s.ignoreFile != "" {
		args = append(args, "--ignore-policy="+s.ignoreFile)
	}
	if s.platform != "" {
		args = append(args, "--platform="+s.platform)
	}
	if s.imageSrc != "" {
		args = append(args, "--image-src="+s.imageSrc)
	}
	// If ignoreErrors is false, we expect a non-zero exit code.
	if s.exitCode != 0 && !ignoreErrors {
		args = append(args, "--exit-code="+strconv.Itoa(s.exitCode))
	}

	args = append(args, ref)
	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, dockerDINDAddress.env()...)
	out, err := cmd.CombinedOutput()

	assert.NoError(t, err, string(out))
}

func (s *scannerCmd) withOutput(p string) *scannerCmd {
	s.output = p
	return s
}

func (s *scannerCmd) withSkipDBUpdate() *scannerCmd {
	s.skipDBUpdate = true
	return s
}

func (s *scannerCmd) withImageSrc(src string) *scannerCmd {
	s.imageSrc = src
	return s
}

func (s *scannerCmd) withIgnoreFile(p string) *scannerCmd {
	s.ignoreFile = p
	return s
}

func (s *scannerCmd) withExitCode(code int) *scannerCmd {
	s.exitCode = code
	return s
}

func (s *scannerCmd) withPlatform(platform string) *scannerCmd {
	s.platform = platform
	return s
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
	cmd.Env = append(cmd.Env, dockerDINDAddress.env()...)
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
	cmd.Env = append(cmd.Env, dockerDINDAddress.env()...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to inspect patched image: %s", string(out))

	var manifest ManifestData
	err = json.Unmarshal(out, &manifest)
	require.NoError(t, err, "failed to parse manifest JSON")

	// Check index-level annotations (Copa metadata)
	assert.NotEmpty(t, manifest.Annotations, "index-level annotations should not be empty")
	assert.Equal(t, "true", manifest.Annotations["copacetic.patched"], "should have Copa patched annotation")
	assert.NotEmpty(t, manifest.Annotations["copacetic.patched.timestamp"], "should have Copa timestamp annotation")
	assert.NotEmpty(t, manifest.Annotations["org.opencontainers.image.created"], "should have created annotation")

	t.Logf("found %d index-level annotations", len(manifest.Annotations))

	// Check manifest-level annotations for each platform
	t.Log("checking manifest-level annotations for patched platforms")

	for _, manifestEntry := range manifest.Manifests {
		platformStr := formatPlatform(manifestEntry.Platform)

		// Only check platforms that actually have vulnerability reports (were patched)
		if isPatchablePlatform(platformStr, platforms, reportDir) {
			t.Logf("checking manifest annotations for patched platform %s", platformStr)

			// Verify that if original nginx annotations exist, they are preserved
			commonAnnotations := []string{
				"org.opencontainers.image.source",
				"org.opencontainers.image.url",
				"org.opencontainers.image.version",
				"org.opencontainers.image.revision",
				"org.opencontainers.image.base.name",
				"org.opencontainers.image.base.digest",
			}

			foundAnnotations := 0
			for _, expectedKey := range commonAnnotations {
				if value, exists := manifestEntry.Annotations[expectedKey]; exists {
					assert.NotEmpty(t, value, "annotation %s should not be empty for platform %s", expectedKey, platformStr)
					t.Logf("platform %s has annotation %s=%s", platformStr, expectedKey, value)
					foundAnnotations++
				}
			}

			// We expect at least some annotations to be preserved for nginx images
			assert.Greater(t, foundAnnotations, 0, "platform %s should have at least some preserved annotations", platformStr)

			// The created timestamp should be updated for patched platforms
			if createdTime, exists := manifestEntry.Annotations["org.opencontainers.image.created"]; exists {
				assert.NotEmpty(t, createdTime, "created timestamp should not be empty for patched platform %s", platformStr)
				t.Logf("platform %s has updated created timestamp: %s", platformStr, createdTime)
			}

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
			t.Logf("skipping platform %s (no vulnerability report, not patched)", platformStr)
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
