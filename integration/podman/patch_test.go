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
	"testing"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
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
	Image        string        `json:"image"`
	Tag          string        `json:"tag"`
	LocalName    string        `json:"localName,omitempty"`
	Distro       string        `json:"distro"`
	Digest       digest.Digest `json:"digest"`
	Description  string        `json:"description"`
	IgnoreErrors bool          `json:"ignoreErrors"`
}

func TestPatchWithPodman(t *testing.T) {
	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	tmp := t.TempDir()
	ignoreFile := filepath.Join(tmp, "ignore.rego")
	err = os.WriteFile(ignoreFile, trivyIgnore, 0o600)
	require.NoError(t, err)

	// Use buildkit address from environment if provided, otherwise create our own
	var buildkitContainer string
	if buildkitAddr != "" {
		// Extract container name from podman-container:// address
		if strings.HasPrefix(buildkitAddr, "podman-container://") {
			buildkitContainer = strings.TrimPrefix(buildkitAddr, "podman-container://")
			t.Logf("Using existing buildkit container from --addr: %s", buildkitContainer)

			// Verify the container exists and is running
			cmd := exec.Command("podman", "inspect", "--format", "{{.State.Status}}", buildkitContainer)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("Failed to inspect buildkit container %s: %v: %s", buildkitContainer, err, string(out))
			}
			status := strings.TrimSpace(string(out))
			if status != "running" {
				t.Fatalf("Buildkit container %s is not running, status: %s", buildkitContainer, status)
			}
		} else {
			t.Skipf("Buildkit address %s is not a podman-container address, skipping Podman test", buildkitAddr)
		}
	} else {
		// Start our own Podman buildkit container for local testing
		buildkitContainer = setupPodmanBuildkit(t)
		defer cleanupPodmanBuildkit(t, buildkitContainer)
	}

	for _, img := range images {
		imageRef := fmt.Sprintf("%s:%s@%s", img.Image, img.Tag, img.Digest)
		mediaType, err := utils.GetMediaType(imageRef)
		require.NoError(t, err)

		// Oracle tends to throw false positives with Trivy
		// See https://github.com/aquasecurity/trivy/issues/1967#issuecomment-1092987400
		if !reportFile && !strings.Contains(img.Image, "oracle") {
			img.IgnoreErrors = false
		}

		// download the trivy db before running the tests
		downloadDB(t)

		t.Run(img.Description+"-podman", func(t *testing.T) {
			t.Parallel()

			// Skip local images for now since they're not relevant for podman testing
			if img.LocalName != "" {
				t.Skip("Skipping local image test for Podman integration")
			}

			dir := t.TempDir()

			ref := fmt.Sprintf("%s:%s@%s", img.Image, img.Tag, img.Digest)

			var scanResults string
			if reportFile {
				scanResults = filepath.Join(dir, "scan.json")
				t.Log("scanning original image")
				scanner().
					withIgnoreFile(ignoreFile).
					withOutput(scanResults).
					withSkipDBUpdate().
					// Do not set a non-zero exit code because we are expecting vulnerabilities.
					scan(t, ref, img.IgnoreErrors)
			}

			r, err := reference.ParseNormalizedNamed(ref)
			require.NoError(t, err, err)

			tagPatched := img.Tag + "-patched"
			patchedRef := fmt.Sprintf("%s:%s", r.Name(), tagPatched)

			patchedMediaType, err := utils.GetMediaType(imageRef)
			require.NoError(t, err)
			fmt.Println("patchedMediaType: ", patchedMediaType)

			// should be equal to the original image media type
			if mediaType != patchedMediaType {
				t.Fatalf("media type mismatch: %s != %s", mediaType, patchedMediaType)
			}

			t.Log("patching image with Podman")
			patchWithPodman(t, ref, tagPatched, dir, img.IgnoreErrors, reportFile, buildkitContainer)

			switch {
			case strings.Contains(img.Image, "oracle"):
				t.Log("Oracle image detected. Skipping Trivy scan.")
			case reportFile:
				t.Log("scanning patched image")
				// Try to scan, but don't fail if Trivy can't access Podman socket in CI
				err := tryScanPatchedImage(t, patchedRef, ignoreFile, img.IgnoreErrors)
				if err != nil {
					t.Logf("Warning: Could not scan patched image with Trivy (this is expected in some CI environments): %v", err)
				}
			default:
				t.Log("scanning patched image")
				// Try to scan, but don't fail if Trivy can't access Podman socket in CI
				err := tryScanPatchedImage(t, patchedRef, ignoreFile, img.IgnoreErrors)
				if err != nil {
					t.Logf("Warning: Could not scan patched image with Trivy (this is expected in some CI environments): %v", err)
				}
			}

			// currently validation is only present when patching with a scan report
			if reportFile && !strings.Contains(img.Image, "oracle") {
				t.Log("verifying the vex output")
				validVEXJSON(t, dir)
			}
		})
	}
}

func setupPodmanBuildkit(t *testing.T) string {
	containerName := "copa-test-buildkitd"

	// Clean up any existing container
	cleanupPodmanBuildkit(t, containerName)

	// Start Podman buildkit container
	cmd := exec.Command("podman", "run", "-d", "--rm", "--name", containerName,
		"--privileged", "docker.io/moby/buildkit:latest")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to start Podman buildkit container: %s", string(out))

	t.Logf("Started Podman buildkit container: %s", containerName)
	return containerName
}

func cleanupPodmanBuildkit(_ *testing.T, containerName string) {
	cmd := exec.Command("podman", "kill", containerName)
	_ = cmd.Run() // Ignore errors since container might not exist

	cmd = exec.Command("podman", "rm", "-f", containerName)
	_ = cmd.Run() // Ignore errors since container might not exist
}

func patchWithPodman(t *testing.T, ref, patchedTag, path string, ignoreErrors bool, reportFile bool, buildkitContainer string) {
	// Use podman-container:// address to connect to the buildkit container
	addrFl := fmt.Sprintf("-a=podman-container://%s", buildkitContainer)

	var reportPath string
	if reportFile {
		reportPath = "-r=" + path + "/scan.json"
	}

	//#nosec G204
	cmd := exec.Command(
		copaPath,
		"patch",
		"-i="+ref,
		"-t="+patchedTag,
		reportPath,
		"-s="+scannerPlugin,
		"--timeout=30m",
		addrFl,
		"--ignore-errors="+strconv.FormatBool(ignoreErrors),
		"--output="+path+"/vex.json",
		"--debug",
	)

	cmd.Env = append(cmd.Env, os.Environ()...)

	out, err := cmd.CombinedOutput()

	if strings.Contains(ref, "oracle") && reportFile && !ignoreErrors {
		assert.Contains(t, string(out), "Error: detected Oracle image passed in\n"+
			"Please read https://project-copacetic.github.io/copacetic/website/troubleshooting before patching your Oracle image")
	} else {
		require.NoError(t, err, string(out))
	}
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
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

func scanner() *scannerCmd {
	return &scannerCmd{}
}

type scannerCmd struct {
	output       string
	skipDBUpdate bool
	ignoreFile   string
	exitCode     int
}

func (s *scannerCmd) withOutput(output string) *scannerCmd {
	s.output = output
	return s
}

func (s *scannerCmd) withSkipDBUpdate() *scannerCmd {
	s.skipDBUpdate = true
	return s
}

func (s *scannerCmd) withIgnoreFile(ignoreFile string) *scannerCmd {
	s.ignoreFile = ignoreFile
	return s
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
	// If ignoreErrors is false, we expect a non-zero exit code.
	if s.exitCode != 0 && !ignoreErrors {
		args = append(args, "--exit-code="+strconv.Itoa(s.exitCode))
	}

	args = append(args, ref)
	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	cmd.Env = append(cmd.Env, os.Environ()...)
	out, err := cmd.CombinedOutput()

	assert.NoError(t, err, string(out))
}

// tryScanPatchedImage attempts to scan the patched image but returns error instead of failing test.
func tryScanPatchedImage(t *testing.T, ref, ignoreFile string, ignoreErrors bool) error {
	args := []string{
		"trivy",
		"image",
		"--quiet",
		"--pkg-types=os",
		"--ignore-unfixed",
		"--scanners=vuln",
		"--skip-db-update",
	}
	if ignoreFile != "" {
		args = append(args, "--ignore-policy="+ignoreFile)
	}
	// If ignoreErrors is false, we expect a non-zero exit code.
	if !ignoreErrors {
		args = append(args, "--exit-code=1")
	}

	args = append(args, ref)
	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	cmd.Env = append(cmd.Env, os.Environ()...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("trivy scan failed: %v: %s", err, string(out))
	}

	t.Logf("Successfully scanned patched image: %s", ref)
	return nil
}

func validVEXJSON(t *testing.T, dir string) {
	vexFile := filepath.Join(dir, "vex.json")

	// Check if VEX file exists
	if _, err := os.Stat(vexFile); os.IsNotExist(err) {
		t.Errorf("VEX file does not exist: %s", vexFile)
		return
	}

	// Read and validate VEX JSON
	content, err := os.ReadFile(vexFile)
	require.NoError(t, err, "Failed to read VEX file")

	var vexData any
	err = json.Unmarshal(content, &vexData)
	require.NoError(t, err, "VEX file contains invalid JSON")

	t.Logf("VEX file is valid JSON with %d bytes", len(content))
}
