package integration

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/opencontainers/go-digest"
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
	Image       string        `json:"image"`
	Tag         string        `json:"tag"`
	Distro      string        `json:"distro"`
	Digest      digest.Digest `json:"digest"`
	Description string        `json:"description"`
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
		img := img
		t.Run(img.Description, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			output := filepath.Join(dir, "output.json")
			ref := fmt.Sprintf("%s:%s@%s", img.Image, img.Tag, img.Digest)
			tagPatched := img.Tag + "-patched"
			patchedRef := fmt.Sprintf("%s:%s", img.Image, tagPatched)

			t.Log("scanning original image")
			scanner().
				withIgnoreFile(ignoreFile).
				withOutput(output).
				// Do not set a non-zero exit code because we are expecting vulnerabilities.
				scan(t, ref)

			t.Log("patching image")
			patch(t, ref, tagPatched, output)

			t.Log("scanning patched image")
			scanner().
				withIgnoreFile(ignoreFile).
				withSkipDBUpdate().
				// here we want a non-zero exit code because we are expecting no vulnerabilities.
				withExitCode(1).
				scan(t, patchedRef)
		})
	}
}

func patch(t *testing.T, ref, patchedTag, scan string) {
	var addrFl string
	if buildkitAddr != "" {
		addrFl = "-a=" + buildkitAddr
	}

	//#nosec G204
	cmd := exec.Command(
		copaPath,
		"patch",
		"-i="+ref,
		"-t="+patchedTag,
		"-r="+scan,
		"--timeout=20m",
		addrFl,
	)
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

func (s *scannerCmd) scan(t *testing.T, ref string) {
	args := []string{
		"trivy",
		"image",
		"--vuln-type=os",
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
	if s.exitCode != 0 {
		args = append(args, "--exit-code="+strconv.Itoa(s.exitCode))
	}

	args = append(args, ref)

	out, err := exec.Command(args[0], args[1:]...).CombinedOutput() //#nosec G204
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
