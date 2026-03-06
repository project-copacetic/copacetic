package golang

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed fixtures/test-images.json
var testImages []byte

type testImage struct {
	Image               string   `json:"image"`
	Tag                 string   `json:"tag"`
	Description         string   `json:"description"`
	Category            string   `json:"category"`
	SkipMainModule      bool     `json:"skipMainModule"`
	ExpectedBinaryCount int      `json:"expectedBinaryCount"`
	BinaryPaths         []string `json:"binaryPaths"`
	LibraryPatchLevel   string   `json:"libraryPatchLevel"`
}

// patchLevel returns the library patch level for the image, defaulting to "major".
func (img *testImage) patchLevel() string {
	if img.LibraryPatchLevel != "" {
		return img.LibraryPatchLevel
	}
	return "major"
}

// Vulnerability defines the fields we need to uniquely identify a vulnerability.
type Vulnerability struct {
	ID      string `json:"VulnerabilityID"`
	PkgName string `json:"PkgName"`
	PkgPath string `json:"PkgPath"`
}

// Key creates a unique identifier for a vulnerability instance.
func (v Vulnerability) Key() string {
	return fmt.Sprintf("%s|%s", v.PkgName, v.ID)
}

// TestGoBinaryPatching tests Go binary patching across diverse images.
func TestGoBinaryPatching(t *testing.T) {
	// Download Trivy DB once before running all sub-tests.
	downloadTrivyDB(t)

	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	for _, img := range images {
		t.Run(img.Description, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			// Build the full image reference.
			ref := img.Image + ":" + img.Tag

			// 1. Scan the original image.
			t.Log("scanning original image for baseline")
			scanResultsFile := filepath.Join(dir, "scan.json")
			vulnsBefore := scanAndParse(t, ref, scanResultsFile, img.SkipMainModule, img.Image)
			require.NotEmpty(t, vulnsBefore, "expected vulnerabilities in the baseline scan")
			t.Logf("Found %d unique vulnerabilities before patching", len(vulnsBefore))

			// Log vulnerable packages for debugging
			pkgSet := make(map[string]bool)
			for _, vuln := range vulnsBefore {
				pkgSet[vuln.PkgName] = true
			}
			t.Logf("Vulnerable packages: %v", mapKeys(pkgSet))

			// 2. Patch the image.
			t.Log("patching image")
			tagPatched := img.Tag + "-patched"
			copaOutput, patchErr := tryPatchImage(t, ref, tagPatched, scanResultsFile, img.patchLevel())

			// Log copa output for debugging
			if testing.Verbose() {
				t.Logf("Copa output:\n%s", copaOutput)
			}

			require.NoError(t, patchErr, fmt.Sprintf("Copa patch failed:\n%s", copaOutput))

			// 3. Scan the patched image.
			t.Log("scanning patched image")
			patchedRef := img.Image + ":" + tagPatched
			vulnsAfter := scanAndParse(t, patchedRef, "", img.SkipMainModule, img.Image)
			t.Logf("Found %d unique vulnerabilities after patching", len(vulnsAfter))

			// 4. Verify the patch was successful.
			t.Logf("Comparing vulnerabilities: Before (%d) vs After (%d)", len(vulnsBefore), len(vulnsAfter))

			assert.Less(t, len(vulnsAfter), len(vulnsBefore),
				"expected fewer vulnerabilities after patching. Before: %d, After: %d. Copa output:\n%s",
				len(vulnsBefore), len(vulnsAfter), copaOutput)

			// 5. Log any new vulnerabilities introduced by transitive dependency changes.
			// Updating Go dependencies can pull in new transitive deps that have their
			// own CVEs. This is inherent to how Go modules work and not a Copa bug.
			// The real success metric is the net reduction (step 4 above).
			newVulns := 0
			for key, vuln := range vulnsAfter {
				if _, existed := vulnsBefore[key]; !existed {
					t.Logf("New vulnerability from transitive dep change: %s in %s", vuln.ID, vuln.PkgName)
					newVulns++
				}
			}
			if newVulns > 0 {
				t.Logf("%d new vulnerabilities introduced by transitive dependency changes (net reduction still positive)", newVulns)
			}

			// 6. Log which vulnerabilities were fixed
			fixed := 0
			for key := range vulnsBefore {
				if _, stillPresent := vulnsAfter[key]; !stillPresent {
					fixed++
				}
			}
			t.Logf("Fixed %d vulnerabilities", fixed)

			// Cleanup patched image.
			_ = exec.Command("docker", "rmi", patchedRef).Run()
		})
	}
}

// TestGoBinaryPatchingByCategory runs tests grouped by image category.
func TestGoBinaryPatchingByCategory(t *testing.T) {
	downloadTrivyDB(t)

	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	// Group images by category
	categories := make(map[string][]testImage)
	for _, img := range images {
		categories[img.Category] = append(categories[img.Category], img)
	}

	for category, imgs := range categories {
		t.Run("Category_"+category, func(t *testing.T) {
			for _, img := range imgs {
				t.Run(img.Description, func(t *testing.T) {
					t.Parallel()

					dir := t.TempDir()
					ref := img.Image + ":" + img.Tag

					// Scan original
					scanResultsFile := filepath.Join(dir, "scan.json")
					vulnsBefore := scanAndParse(t, ref, scanResultsFile, img.SkipMainModule, img.Image)
					if len(vulnsBefore) == 0 {
						t.Skip("no vulnerabilities found in baseline scan")
					}

					// Patch
					tagPatched := img.Tag + "-patched-" + category
					copaOutput, patchErr := tryPatchImage(t, ref, tagPatched, scanResultsFile, img.patchLevel())
					require.NoError(t, patchErr, fmt.Sprintf("Copa patch failed:\n%s", copaOutput))

					// Verify
					patchedRef := img.Image + ":" + tagPatched
					vulnsAfter := scanAndParse(t, patchedRef, "", img.SkipMainModule, img.Image)

					assert.Less(t, len(vulnsAfter), len(vulnsBefore),
						"category %s: expected fewer vulnerabilities", category)

					_ = exec.Command("docker", "rmi", patchedRef).Run()
				})
			}
		})
	}
}

// TestMultiBinaryImages specifically tests images with multiple Go binaries.
func TestMultiBinaryImages(t *testing.T) {
	downloadTrivyDB(t)

	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	for _, img := range images {
		if img.ExpectedBinaryCount <= 1 {
			continue
		}

		t.Run(img.Description, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			ref := img.Image + ":" + img.Tag

			// Scan
			scanResultsFile := filepath.Join(dir, "scan.json")
			vulnsBefore := scanAndParse(t, ref, scanResultsFile, img.SkipMainModule, img.Image)
			if len(vulnsBefore) == 0 {
				t.Skip("no vulnerabilities found")
			}

			t.Logf("Testing multi-binary image with %d expected binaries: %v",
				img.ExpectedBinaryCount, img.BinaryPaths)

			// Patch
			tagPatched := img.Tag + "-multi-patched"
			copaOutput, patchErr := tryPatchImage(t, ref, tagPatched, scanResultsFile, img.patchLevel())
			require.NoError(t, patchErr, fmt.Sprintf("Copa patch failed:\n%s", copaOutput))

			// Verify binaries are mentioned in output
			for _, binaryPath := range img.BinaryPaths {
				// Check if binary was processed (logged in copa output)
				assert.Contains(t, copaOutput, binaryPath,
					"expected binary %s to be processed", binaryPath)
			}

			// Verify vulnerabilities reduced
			patchedRef := img.Image + ":" + tagPatched
			vulnsAfter := scanAndParse(t, patchedRef, "", img.SkipMainModule, img.Image)

			assert.Less(t, len(vulnsAfter), len(vulnsBefore),
				"expected fewer vulnerabilities in multi-binary image")

			_ = exec.Command("docker", "rmi", patchedRef).Run()
		})
	}
}

// TestDistrolessImages specifically tests distroless (no shell) images.
func TestDistrolessImages(t *testing.T) {
	downloadTrivyDB(t)

	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	distrolessCategories := map[string]bool{
		"distroless": true,
		"scratch":    true,
	}

	for _, img := range images {
		if !distrolessCategories[img.Category] {
			continue
		}

		t.Run(img.Description, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			ref := img.Image + ":" + img.Tag

			// Scan
			scanResultsFile := filepath.Join(dir, "scan.json")
			vulnsBefore := scanAndParse(t, ref, scanResultsFile, img.SkipMainModule, img.Image)
			if len(vulnsBefore) == 0 {
				t.Skip("no vulnerabilities found")
			}

			t.Logf("Testing distroless/scratch image: %s (category: %s)", ref, img.Category)

			// Patch - this should work without shell in target
			tagPatched := img.Tag + "-distroless-patched"
			copaOutput, patchErr := tryPatchImage(t, ref, tagPatched, scanResultsFile, img.patchLevel())
			require.NoError(t, patchErr, fmt.Sprintf("Copa patch failed:\n%s", copaOutput))

			// Should not see shell-related errors
			assert.NotContains(t, copaOutput, "executable file not found",
				"distroless patching should not require shell")

			// Verify vulnerabilities reduced
			patchedRef := img.Image + ":" + tagPatched
			vulnsAfter := scanAndParse(t, patchedRef, "", img.SkipMainModule, img.Image)

			assert.Less(t, len(vulnsAfter), len(vulnsBefore),
				"expected fewer vulnerabilities in distroless image")

			_ = exec.Command("docker", "rmi", patchedRef).Run()
		})
	}
}

func downloadTrivyDB(t *testing.T) {
	t.Helper()
	cmd := exec.Command("trivy", "image", "--download-db-only")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to download trivy db:\n%s", string(output))
}

func scanAndParse(t *testing.T, image string, outputFile string, skipMainModule bool, imageName string) map[string]Vulnerability {
	t.Helper()

	if outputFile == "" {
		f, err := os.CreateTemp(t.TempDir(), "scan-*.json")
		require.NoError(t, err)
		outputFile = f.Name()
		f.Close()
	}

	args := []string{
		"trivy", "image",
		"--quiet",
		"--format=json",
		"-o=" + outputFile,
		"--pkg-types=library",
		"--ignore-unfixed",
		"--skip-db-update",
		image,
	}

	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("trivy scan failed: %v\nOutput: %s", err, string(output))
		require.NoError(t, err, "trivy scan failed")
	}

	reportBytes, err := os.ReadFile(outputFile)
	require.NoError(t, err, "failed to read trivy report file")

	var report struct {
		Results []struct {
			Type            string          `json:"Type"`
			Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	err = json.Unmarshal(reportBytes, &report)
	require.NoError(t, err, "failed to unmarshal trivy report")

	vulns := make(map[string]Vulnerability)
	for _, result := range report.Results {
		// Only consider gobinary results.
		if result.Type != "gobinary" {
			continue
		}
		for _, v := range result.Vulnerabilities {
			// Skip main module vulnerabilities if configured.
			// Main module vulns cannot be patched without rebuilding the entire app.
			if skipMainModule && isMainModuleVuln(v.PkgName, imageName) {
				continue
			}
			vulns[v.Key()] = v
		}
	}

	return vulns
}

// isMainModuleVuln checks if a vulnerability is in the main module.
// Main module packages typically match the image name pattern.
func isMainModuleVuln(pkgName, image string) bool {
	// Extract the likely main module name from the image.
	// e.g., "coredns/coredns" -> "coredns"
	// e.g., "traefik" -> "traefik"
	parts := strings.Split(image, "/")
	imageName := parts[len(parts)-1]
	imageName = strings.Split(imageName, ":")[0]

	return strings.Contains(strings.ToLower(pkgName), strings.ToLower(imageName))
}

func tryPatchImage(t *testing.T, image, tag, reportFile, patchLevel string) (string, error) {
	t.Helper()

	args := []string{
		"patch",
		"-i=" + image,
		"-r=" + reportFile,
		"-t=" + tag,
		"--pkg-types=os,library",
		"--library-patch-level=" + patchLevel,
		"--timeout=15m",
		"--debug",
	}

	if buildkitAddr != "" {
		args = append(args, "-a="+buildkitAddr)
	}

	cmd := exec.Command(copaPath, args...) //#nosec G204
	cmd.Env = append(os.Environ(), "COPA_EXPERIMENTAL=1")
	out, err := cmd.CombinedOutput()

	return string(out), err
}

// mapKeys returns the keys of a map as a slice.
func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
