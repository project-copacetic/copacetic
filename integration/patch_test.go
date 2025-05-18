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

func TestPatch(t *testing.T) {
	var images []testImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	tmp := t.TempDir()
	ignoreFile := filepath.Join(tmp, "ignore.rego")
	err = os.WriteFile(ignoreFile, trivyIgnore, 0o600)
	require.NoError(t, err)

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

			t.Log("patching image")
			patch(t, ref, tagPatched, dir, img.IgnoreErrors, reportFile)

			switch {
			case strings.Contains(img.Image, "oracle"):
				t.Log("Oracle image detected. Skipping Trivy scan.")
			case reportFile:
				t.Log("scanning patched image")
				scanner().
					withIgnoreFile(ignoreFile).
					withSkipDBUpdate().
					// here we want a non-zero exit code because we are expecting no vulnerabilities.
					withExitCode(1).
					scan(t, patchedRef, img.IgnoreErrors)
			default:
				t.Log("scanning patched image")
				scanner().
					withIgnoreFile(ignoreFile).
					withSkipDBUpdate().
					// here we want a non-zero exit code because we are expecting no vulnerabilities.
					withExitCode(1).
					scan(t, patchedRef, img.IgnoreErrors)
			}

			// currently validation is only present when patching with a scan report
			if reportFile && !strings.Contains(img.Image, "oracle") {
				t.Log("verifying the vex output")
				validVEXJSON(t, dir)
			}
		})
	}
}

func dockerPull(t *testing.T, ref string) {
	dockerCmd(t, `pull`, ref)
}

func dockerTag(t *testing.T, ref, newRef string) {
	dockerCmd(t, `tag`, ref, newRef)
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

func dockerCmd(t *testing.T, args ...string) {
	var err error
	if len(args) == 0 {
		err = fmt.Errorf("no args provided")
	}
	require.NoError(t, err, "no args provided")

	a := []string{}

	if addr := dockerDINDAddress.addr(); addr != "" {
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
	cmd.Env = append(cmd.Env, dockerDINDAddress.env()...)

	out, err := cmd.CombinedOutput()

	if strings.Contains(ref, "oracle") && reportFile && !ignoreErrors {
		assert.Contains(t, string(out), "Error: detected Oracle image passed in\n"+
			"Please read https://project-copacetic.github.io/copacetic/website/troubleshooting before patching your Oracle image")
	} else {
		require.NoError(t, err, string(out))
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

func (s *scannerCmd) withIgnoreFile(p string) *scannerCmd {
	s.ignoreFile = p
	return s
}

func (s *scannerCmd) withExitCode(code int) *scannerCmd {
	s.exitCode = code
	return s
}

func validVEXJSON(t *testing.T, path string) {
	file, err := os.ReadFile(filepath.Join(path, "vex.json"))
	require.NoError(t, err)
	isValid := json.Valid(file)
	assert.True(t, isValid, "vex.json is not valid json")
}
