package integration

import (
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
	scanner().
		withOutput(reportPath).
		withSkipDBUpdate().
		withPlatform(platformToScan).
		scan(t, localRef, false)

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
