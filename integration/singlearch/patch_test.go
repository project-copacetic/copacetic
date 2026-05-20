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
	Image          string        `json:"image"`
	Tag            string        `json:"tag"`
	LocalName      string        `json:"localName,omitempty"`
	Distro         string        `json:"distro"`
	Digest         digest.Digest `json:"digest"`
	Description    string        `json:"description"`
	IgnoreErrors   bool          `json:"ignoreErrors"`
	IsManifestList bool          `json:"isManifestList"`
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

	// Download the trivy db once to a shared cache directory
	sharedCacheDir := filepath.Join(tmp, "trivy-shared-cache")
	common.DownloadDBToDir(t, sharedCacheDir, common.DockerDINDAddress.Env()...)

	for _, img := range images {
		// Oracle tends to throw false positives with Trivy
		// See https://github.com/aquasecurity/trivy/issues/1967#issuecomment-1092987400
		if !reportFile && !strings.Contains(img.Image, "oracle") {
			img.IgnoreErrors = false
		}

		t.Run(img.Description, func(t *testing.T) {
			t.Parallel()

			// Each parallel subtest gets its own cache dir to avoid Trivy lock contention
			testCacheDir := common.CopyCacheDir(t, sharedCacheDir)

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
					WithCacheDir(testCacheDir).
					// Do not set a non-zero exit code because we are expecting vulnerabilities.
					Scan(t, ref, img.IgnoreErrors, common.DockerDINDAddress.Env()...)
			}

			r, err := reference.ParseNormalizedNamed(ref)
			require.NoError(t, err, err)

			tagPatched := img.Tag + "-patched"

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

			// Validate that patching preserved the original image's manifest media type.
			// Both refs are inspected after patching: the original is locally available
			// (either via dockerPull above or pulled by buildkit during patching) and
			// the patched image is loaded into the local daemon by copa.
			mediaType, err := utils.GetMediaType(ref, imageloader.Docker)
			require.NoError(t, err)
			patchedMediaType, err := utils.GetMediaType(patchedRef, imageloader.Docker)
			require.NoError(t, err)
			if mediaType != patchedMediaType {
				t.Fatalf("media type mismatch: %s != %s", mediaType, patchedMediaType)
			}

			switch {
			case strings.Contains(img.Image, "oracle"):
				t.Log("Oracle image detected. Skipping Trivy scan.")
			case reportFile:
				t.Log("scanning patched image")
				common.NewScanner().
					WithIgnoreFile(ignoreFile).
					WithSkipDBUpdate().
					WithCacheDir(testCacheDir).
					// here we want a non-zero exit code because we are expecting no vulnerabilities.
					WithExitCode(1).
					Scan(t, patchedRef, img.IgnoreErrors, common.DockerDINDAddress.Env()...)
			default:
				t.Log("scanning patched image")
				common.NewScanner().
					WithIgnoreFile(ignoreFile).
					WithSkipDBUpdate().
					WithCacheDir(testCacheDir).
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
		assert.Contains(t, string(out), "detected Oracle image passed in\n"+
			"Please read https://project-copacetic.github.io/copacetic/website/troubleshooting before patching your Oracle image")
	} else {
		require.NoError(t, err, string(out))
	}
}

// TestPatchDaemonOnlyImage exercises the daemon-only patching path: an image
// is loaded into the local Docker daemon and re-tagged with a non-resolvable
// registry hostname (127.0.0.1:1, which immediately refuses connections). If
// any copa code path falls back to a remote registry lookup instead of using
// the local image store, the patch attempt will surface a "connection refused"
// log line — which this test asserts on. This is the missing test pattern that
// has historically masked local-first regressions (e.g. PR #1614), because
// other singlearch fixtures with localName entries are rescued by the graceful
// fallback in patch.go and still succeed when the registry call fails.
//
// Only runs when the buildkit instance is the docker daemon itself
// (COPA_BUILDKIT_ADDR starts with `docker://`); for other backends the patch
// hand-off cannot resolve a daemon-only ref and the scenario is moot.
func TestPatchDaemonOnlyImage(t *testing.T) {
	if !strings.HasPrefix(os.Getenv("COPA_BUILDKIT_ADDR"), "docker://") {
		t.Skip("daemon-only patching requires COPA_BUILDKIT_ADDR=docker://...")
	}

	// Use a small, stable image from the existing fixtures so we don't pull
	// anything new. The digest pins the content to make the test reproducible.
	const (
		source     = "docker.io/library/nginx:1.21.6@sha256:2bcabc23b45489fb0885d69a06ba1d648aeda973fae7bb981bafbb884165e514"
		daemonOnly = "127.0.0.1:1/copa-daemon-only:original"
		bogusHost  = "127.0.0.1:1"
	)

	dockerPull(t, source)
	dockerTag(t, source, daemonOnly)
	t.Cleanup(func() {
		// Best-effort cleanup; we don't fail the test if the tag is gone.
		_ = exec.Command("docker", "rmi", daemonOnly).Run()
	})

	dir := t.TempDir()

	addrFl := "-a=" + os.Getenv("COPA_BUILDKIT_ADDR")
	cmd := exec.Command(
		copaPath,
		"patch",
		"-i="+daemonOnly,
		"-t=patched",
		"-s="+scannerPlugin,
		"--timeout=30m",
		addrFl,
		"--platform=linux/amd64",
		"--ignore-errors=true",
		"--output="+dir+"/vex.json",
		"--debug",
	)
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, common.DockerDINDAddress.Env()...)

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "daemon-only patch must succeed without any remote registry access:\n%s", string(out))

	// Any registry attempt to the bogus hostname produces a "connection refused"
	// (or "no route to host") error mentioning the host. If copa correctly uses
	// the local image store, no such error is logged.
	assert.NotContains(
		t,
		string(out),
		bogusHost+`": dial`,
		"copa attempted to contact the unresolvable registry %q — local-first lookup regressed; output was:\n%s",
		bogusHost,
		string(out),
	)
	assert.NotContains(
		t,
		string(out),
		"connection refused",
		"copa attempted to contact a registry that refused connection — local-first lookup regressed; output was:\n%s",
		string(out),
	)
}
