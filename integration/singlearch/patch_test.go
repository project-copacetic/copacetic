package integration

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/integration/common"
	"github.com/project-copacetic/copacetic/integration/testenv"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/require"
)

//go:embed fixtures/test-images.json
var testImages []byte

type testImage struct {
	Image        string        `json:"image"`
	Tag          string        `json:"tag"`
	LocalName    string        `json:"localName,omitempty"`
	Distro       string        `json:"distro"`
	Digest       digest.Digest `json:"digest"`
	Description  string        `json:"description"`
	IgnoreErrors bool          `json:"ignoreErrors"`
}

func TestPatch(t *testing.T) {
	env := testenv.New(t)
	defer env.Teardown()

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
		common.DownloadDB(t, common.DockerDINDAddress.Env(env.Buildkit.Address)...)

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
				dockerPull(t, env.Buildkit.Address, ref)
				dockerTag(t, env.Buildkit.Address, ref, img.LocalName)
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
					Scan(t, ref, img.IgnoreErrors, common.DockerDINDAddress.Env(env.Buildkit.Address)...)
			}

			r, err := reference.ParseNormalizedNamed(ref)
			require.NoError(t, err, err)

			tagPatched := img.Tag + "-patched"
			patchedRef := fmt.Sprintf("%s:%s", r.Name(), tagPatched)

			patchedMediaType, err := utils.GetMediaType(imageRef, imageloader.Docker)
			require.NoError(t, err)
			fmt.Println("patchedMediaType: ", patchedMediaType)

			// should be equal to the original image media type
			if mediaType != patchedMediaType {
				t.Fatalf("media type mismatch: %s != %s", mediaType, patchedMediaType)
			}

			t.Log("patching image")
			common.Patch(
				t, ref, tagPatched, dir, ignoreErrors, reportFile,
				buildkitAddr, copaPath, scannerPlugin, common.DockerDINDAddress.Env(env.Buildkit.Address), false, false,
			)

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
					Scan(t, patchedRef, img.IgnoreErrors, common.DockerDINDAddress.Env(env.Buildkit.Address)...)
			default:
				t.Log("scanning patched image")
				common.NewScanner().
					WithIgnoreFile(ignoreFile).
					WithSkipDBUpdate().
					// here we want a non-zero exit code because we are expecting no vulnerabilities.
					WithExitCode(1).
					Scan(t, patchedRef, img.IgnoreErrors, common.DockerDINDAddress.Env(env.Buildkit.Address)...)
			}

			// currently validation is only present when patching with a scan report
			if reportFile && !strings.Contains(img.Image, "oracle") {
				t.Log("verifying the vex output")
				common.ValidateVEXJSON(t, dir)
			}
		})
	}
}

func dockerPull(t *testing.T, buildkitAddr string, ref string) {
	dockerCmd(t, buildkitAddr, `pull`, ref)
}

func dockerTag(t *testing.T, ref, buildkitAddr string, newRef string) {
	dockerCmd(t, buildkitAddr, `tag`, ref, newRef)
}

func dockerCmd(t *testing.T, buildkitAddr string, args ...string) {
	var err error
	if len(args) == 0 {
		err = fmt.Errorf("no args provided")
	}
	require.NoError(t, err, "no args provided")

	a := []string{}

	if addr := common.DockerDINDAddress.Addr(buildkitAddr); addr != "" {
		a = append(a, "-H", addr)
	}

	a = append(a, args...)

	cmd := exec.Command(`docker`, a...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
