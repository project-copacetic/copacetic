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

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/integration/common"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed fixtures/test-images.json
var testImages []byte

type testImage struct {
	Image              string        `json:"image"`
	Tag                string        `json:"tag"`
	LocalName          string        `json:"localName,omitempty"`
	Distro             string        `json:"distro"`
	Digest             digest.Digest `json:"digest"`
	Description        string        `json:"description"`
	IgnoreErrors       bool          `json:"ignoreErrors"`
	IsManifestList     bool          `json:"isManifestList"`
	PkgTypes           string        `json:"pkgTypes,omitempty"`
	LibraryPatchLevels []string      `json:"libraryPatchLevels,omitempty"`
}

type manifestPlatform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

func TestPatch(t *testing.T) {
	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	tmp := t.TempDir()
	ignoreFile := filepath.Join(tmp, "ignore.rego")
	err = os.WriteFile(ignoreFile, common.TrivyIgnore, 0o600)
	require.NoError(t, err)

	for _, img := range images {
		imageRef := fmt.Sprintf("%s:%s@%s", img.Image, img.Tag, img.Digest)
		mediaType, err := utils.GetMediaType(imageRef, imageloader.Docker)
		require.NoError(t, err)

		// Oracle tends to throw false positives with Trivy
		// See https://github.com/aquasecurity/trivy/issues/1967#issuecomment-1092987400
		if !reportFile && !strings.Contains(img.Image, "oracle") {
			img.IgnoreErrors = false
		}

		// download the trivy db before running the tests
		common.DownloadDB(t, common.DockerDINDAddress.Env()...)

		t.Run(img.Description, func(t *testing.T) {
			t.Parallel()

			// Only the buildkit instance running within the docker daemon can work
			// with locally-built or locally-tagged images. As a result, skip tests
			// for local-only images when the daemon in question is not docker itself.
			// i.e., don't test local images in buildx or with stock buildkit.
			if img.LocalName != "" && !strings.HasPrefix(os.Getenv(`COPA_BUILDKIT_ADDR`), "docker://") {
				t.Skip()
			}

			dir := t.TempDir()

			ref := fmt.Sprintf("%s:%s@%s", img.Image, img.Tag, img.Digest)
			if img.LocalName != "" {
				dockerPull(t, ref)
				dockerTag(t, ref, img.LocalName)
				ref = img.LocalName
			}

			var scanResults string
			if reportFile {
				scanResults = filepath.Join(dir, "scan.json")
				t.Log("scanning original image")
				common.NewScanner().
					WithIgnoreFile(ignoreFile).
					WithOutput(scanResults).
					WithSkipDBUpdate().
					// Do not set a non-zero exit code because we are expecting vulnerabilities.
					Scan(t, ref, img.IgnoreErrors, common.DockerDINDAddress.Env()...)
			}

			r, err := reference.ParseNormalizedNamed(ref)
			require.NoError(t, err, err)

			tagPatched := img.Tag + "-patched"

			patchedMediaType, err := utils.GetMediaType(imageRef, imageloader.Docker)
			require.NoError(t, err)
			fmt.Println("patchedMediaType: ", patchedMediaType)

			// should be equal to the original image media type
			if mediaType != patchedMediaType {
				t.Fatalf("media type mismatch: %s != %s", mediaType, patchedMediaType)
			}

			t.Log("patching image")
			patch(t, ref, tagPatched, dir, img.IgnoreErrors, reportFile)

			// For no-report tests with manifest images, Copa creates platform-specific tags like "-patched-amd64"
			// The scanning should look for the tag that Copa actually created
			scanTag := tagPatched
			if !reportFile && img.IsManifestList {
				hostPlatform := platforms.DefaultSpec().Architecture
				imagePlatforms := getManifestPlatforms(t, ref)

				found := false
				for _, p := range imagePlatforms {
					if p.Architecture == hostPlatform {
						found = true
						break
					}
				}

				targetArch := hostPlatform
				if !found && len(imagePlatforms) > 0 {
					targetArch = imagePlatforms[0].Architecture
				}
				scanTag += "-" + targetArch
			}
			patchedRef := fmt.Sprintf("%s:%s", r.Name(), scanTag)

			switch {
			case strings.Contains(img.Image, "oracle"):
				t.Log("Oracle image detected. Skipping Trivy scan.")
			case reportFile:
				t.Log("scanning patched image")
				common.NewScanner().
					WithIgnoreFile(ignoreFile).
					WithSkipDBUpdate().
					// here we want a non-zero exit code because we are expecting no vulnerabilities.
					WithExitCode(1).
					Scan(t, patchedRef, img.IgnoreErrors, common.DockerDINDAddress.Env()...)
			default:
				t.Log("scanning patched image")
				common.NewScanner().
					WithIgnoreFile(ignoreFile).
					WithSkipDBUpdate().
					// here we want a non-zero exit code because we are expecting no vulnerabilities.
					WithExitCode(1).
					Scan(t, patchedRef, img.IgnoreErrors, common.DockerDINDAddress.Env()...)
			}

			// currently validation is only present when patching with a scan report
			if reportFile && !strings.Contains(img.Image, "oracle") {
				t.Log("verifying the vex output")
				common.ValidateVEXJSON(t, dir)
			}
		})
	}
}

func getManifestPlatforms(t *testing.T, imageRef string) []manifestPlatform {
	validPlatforms := map[string]bool{
		"linux/386":      true,
		"linux/amd64":    true,
		"linux/arm":      true,
		"linux/arm/v5":   true,
		"linux/arm/v6":   true,
		"linux/arm/v7":   true,
		"linux/arm64":    true,
		"linux/arm64/v8": true,
		"linux/ppc64le":  true,
		"linux/s390x":    true,
		"linux/riscv64":  true,
	}

	cmd := exec.Command("docker", "manifest", "inspect", imageRef)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	var manifest struct {
		Manifests []struct {
			Platform manifestPlatform `json:"platform"`
		} `json:"manifests"`
	}
	err = json.Unmarshal(output, &manifest)
	require.NoError(t, err, "failed to parse manifest JSON")

	var filteredPlatforms []manifestPlatform
	for _, m := range manifest.Manifests {
		p := m.Platform
		platformStr := p.OS + "/" + p.Architecture
		if p.Variant != "" {
			platformStr += "/" + p.Variant
		}

		if _, ok := validPlatforms[platformStr]; ok {
			filteredPlatforms = append(filteredPlatforms, p)
		}
	}
	return filteredPlatforms
}

func dockerPull(t *testing.T, ref string) {
	dockerCmd(t, `pull`, ref)
}

func dockerTag(t *testing.T, ref, newRef string) {
	dockerCmd(t, `tag`, ref, newRef)
}

func dockerCmd(t *testing.T, args ...string) {
	var err error
	if len(args) == 0 {
		err = fmt.Errorf("no args provided")
	}
	require.NoError(t, err, "no args provided")

	a := []string{}

	if addr := common.DockerDINDAddress.Addr(); addr != "" {
		a = append(a, "-H", addr)
	}

	a = append(a, args...)

	cmd := exec.Command(`docker`, a...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

func patch(t *testing.T, ref, patchedTag, path string, ignoreErrors bool, reportFile bool) {
	var addrFl string
	if buildkitAddr != "" {
		addrFl = "-a=" + buildkitAddr
	}

	var reportPath string
	if reportFile {
		reportPath = "-r=" + path + "/scan.json"
	}

	var platformFlag string
	if !reportFile {
		platformFlag = "--platform=linux/amd64"
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
		platformFlag,
		"--ignore-errors="+strconv.FormatBool(ignoreErrors),
		"--output="+path+"/vex.json",
		"--debug",
	)

	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, common.DockerDINDAddress.Env()...)

	out, err := cmd.CombinedOutput()

	if strings.Contains(ref, "oracle") && reportFile && !ignoreErrors {
		assert.Contains(t, string(out), "Error: detected Oracle image passed in\n"+
			"Please read https://project-copacetic.github.io/copacetic/website/troubleshooting before patching your Oracle image")
	} else {
		require.NoError(t, err, string(out))
	}
}

// TestPatchLibraries tests patching library vulnerabilities using experimental features.
func TestPatchLibraries(t *testing.T) {
	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	// Filter to only images that support library patching
	var libraryImages []testImage
	for _, img := range images {
		if strings.Contains(img.PkgTypes, "library") && len(img.LibraryPatchLevels) > 0 {
			libraryImages = append(libraryImages, img)
		}
	}

	if len(libraryImages) == 0 {
		t.Skip("No library-capable images found in test configuration")
	}

	tmp := t.TempDir()
	ignoreFile := filepath.Join(tmp, "ignore.rego")
	err = os.WriteFile(ignoreFile, common.TrivyIgnore, 0o600)
	require.NoError(t, err)

	for _, img := range libraryImages {
		imageRef := fmt.Sprintf("%s:%s@%s", img.Image, img.Tag, img.Digest)

		// download the trivy db before running the tests
		common.DownloadDB(t, common.DockerDINDAddress.Env()...)

		for _, patchLevel := range img.LibraryPatchLevels {
			testName := fmt.Sprintf("%s-library-%s", img.Description, patchLevel)
			t.Run(testName, func(t *testing.T) {
				t.Parallel()

				dir := t.TempDir()

				ref := imageRef
				if img.LocalName != "" {
					dockerPull(t, ref)
					dockerTag(t, ref, img.LocalName)
					ref = img.LocalName
				}

				// Create scan report with library packages
				scanResults := filepath.Join(dir, "scan.json")
				t.Log("scanning original image with package types:", img.PkgTypes)
				common.NewScanner().
					WithIgnoreFile(ignoreFile).
					WithOutput(scanResults).
					WithSkipDBUpdate().
					WithPkgTypes(img.PkgTypes).
					// Do not set a non-zero exit code because we are expecting vulnerabilities.
					Scan(t, ref, img.IgnoreErrors, common.DockerDINDAddress.Env()...)

				r, err := reference.ParseNormalizedNamed(ref)
				require.NoError(t, err)

				patchedTag := img.Tag + "-library-" + patchLevel + "-patched"
				patchedRef := fmt.Sprintf("%s:%s", r.Name(), patchedTag)

				t.Logf("patching image with package types %s using patch level: %s", img.PkgTypes, patchLevel)
				patchSingleWithLibrarySupport(t, ref, patchedTag, scanResults, dir, img.IgnoreErrors, img.PkgTypes, patchLevel)

				// Verify the patched image doesn't have the same vulnerabilities
				// For manifest lists, get supported platform and test against it
				scanTag := patchedTag
				if img.IsManifestList {
					hostPlatform := platforms.DefaultSpec().Architecture
					imagePlatforms := getManifestPlatforms(t, ref)

					found := false
					for _, p := range imagePlatforms {
						if p.Architecture == hostPlatform {
							found = true
							break
						}
					}

					targetArch := hostPlatform
					if !found && len(imagePlatforms) > 0 {
						targetArch = imagePlatforms[0].Architecture
					}
					scanTag += "-" + targetArch
					patchedRef = fmt.Sprintf("%s:%s", r.Name(), scanTag)
				}

				t.Log("scanning patched image for vulnerabilities")
				common.NewScanner().
					WithIgnoreFile(ignoreFile).
					WithSkipDBUpdate().
					WithPkgTypes(img.PkgTypes).
					// here we want a non-zero exit code because we are expecting no vulnerabilities.
					WithExitCode(1).
					Scan(t, patchedRef, img.IgnoreErrors, common.DockerDINDAddress.Env()...)

				t.Log("verifying the vex output")
				common.ValidateVEXJSON(t, dir)
			})
		}
	}
}

// patchSingleWithLibrarySupport patches a single architecture image with library support enabled.
func patchSingleWithLibrarySupport(t *testing.T, ref, patchedTag, scanResults, path string, ignoreErrors bool, pkgTypes, libraryPatchLevel string) {
	var addrFl string
	if buildkitAddr != "" {
		addrFl = "-a=" + buildkitAddr
	}

	var reportPath string
	if scanResults != "" {
		reportPath = "-r=" + scanResults
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
		"--platform=linux/amd64",
		"--ignore-errors="+strconv.FormatBool(ignoreErrors),
		"--output="+path+"/vex.json",
		"--pkg-types="+pkgTypes,
		"--library-patch-level="+libraryPatchLevel,
		"--debug",
	)

	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, common.DockerDINDAddress.Env()...)
	// Enable experimental features for library patching
	cmd.Env = append(cmd.Env, "COPA_EXPERIMENTAL=1")

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
