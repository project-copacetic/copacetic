package multiplatformplugin

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

	"github.com/stretchr/testify/require"
)

//go:embed fixtures/test-images.json
var testImages []byte

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

func TestMultiArchPluginPatch(t *testing.T) {
	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	for _, img := range images {
		t.Run(img.Description, func(t *testing.T) {
			// define a few variables
			ref := fmt.Sprintf("%s:%s", img.LocalImage, img.Tag)
			originalImageRef := fmt.Sprintf("%s:%s", img.OriginalImage, img.Tag)

			// copy over the original image to the local image using oras
			copyImage(t, originalImageRef, ref)

			reportDir := t.TempDir()

			t.Log("creating scan reports for each platform using scanner plugin")
			var wg sync.WaitGroup
			for _, platformStr := range img.Platforms {
				wg.Add(1)
				go func() {
					defer wg.Done()

					suffix := strings.ReplaceAll(platformStr, "/", "-")
					reportPath := filepath.Join(reportDir, "report-"+suffix+".json")

					t.Logf("generating fake report for platform %s", platformStr)
					generateFakeReport(t, platformStr, reportPath)
				}()
			}
			wg.Wait()

			tagPatched := img.Tag + "-patched"
			patchedRef := fmt.Sprintf("%s:%s", img.LocalImage, tagPatched)

			t.Log("patching image with multiple architectures using scanner plugin")
			patchMultiPlatformWithPlugin(t, ref, tagPatched, reportDir, img.IgnoreErrors, img.Push)

			t.Log("verifying patched image for each platform")
			wg = sync.WaitGroup{}
			for _, platformStr := range img.Platforms {
				wg.Add(1)
				go func() {
					defer wg.Done()
					parts := strings.Split(platformStr, "/")
					archStr := strings.Split(platformStr, "/")[1]
					patchedArchRef := fmt.Sprintf("%s-%s", patchedRef, archStr)
					if len(parts) > 2 {
						variantStr := strings.Split(platformStr, "/")[2]
						patchedArchRef += "-" + variantStr
					}

					// check if the patched image exists
					cmd := exec.Command("docker", "image", "inspect", patchedArchRef)
					out, err := cmd.CombinedOutput()
					require.NoError(t, err, string(out))
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

func patchMultiPlatformWithPlugin(t *testing.T, ref, patchedTag, reportDir string, ignoreErrors, push bool) {
	var addrFl string
	if buildkitAddr != "" {
		addrFl = "-a=" + buildkitAddr
	}

	args := []string{
		"patch",
		"-i=" + ref,
		"-t=" + patchedTag,
		"--report=" + reportDir,
		"-s=" + scannerPluginName,
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

func generateFakeReport(t *testing.T, platform string, output string) {
	var arch string
	parts := strings.Split(platform, "/")
	if len(parts) >= 2 {
		arch = parts[1]
	}

	fakeReport := `{
		"OSType": "debian",
		"OSVersion": "12",
		"Arch": "` + arch + `",
		"Packages": [
			{
				"Name": "libssl3",
				"InstalledVersion": "3.0.11-1~deb12u2",
				"FixedVersion": "3.0.11-1~deb12u2+deb12u1",
				"VulnerabilityID": "CVE-2021-44228"
			}
		]
	}`

	err := os.WriteFile(output, []byte(fakeReport), 0o600)
	require.NoError(t, err)
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
