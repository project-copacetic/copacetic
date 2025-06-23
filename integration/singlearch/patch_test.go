package integration

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/project-copacetic/copacetic/test/helpers"
	"github.com/project-copacetic/copacetic/test/testenv"
	"github.com/stretchr/testify/require"
)

var (
	//go:embed fixtures/test-images.json
	testImages []byte

	//go:embed fixtures/trivy_ignore.rego
	trivyIgnore []byte

	env *testenv.Env
)

type TestImage struct {
	Image        string `json:"image"`
	Tag          string `json:"tag"`
	Digest       string `json:"digest"`
	Distro       string `json:"distro"`
	Description  string `json:"description"`
	LocalName    string `json:"localName"`
	IgnoreErrors bool   `json:"ignoreErrors"`
}

func TestSingleArchPatch(t *testing.T) {
	env = testenv.New(t)

	var images []TestImage
	err := json.Unmarshal(testImages, &images)
	require.NoError(t, err)

	tmp := t.TempDir()
	ignoreFile := filepath.Join(tmp, "ignore.rego")
	err = helpers.WriteFile(ignoreFile, trivyIgnore)
	require.NoError(t, err)

	helpers.DownloadTrivyDB(t)

	for _, img := range images {
		t.Run(img.Description, func(t *testing.T) {
			t.Parallel()

			localName := img.LocalName
			if localName == "" {
				// Fallback to the image name (strip registry if needed)
				parts := strings.Split(img.Image, "/")
				localName = parts[len(parts)-1]
			}
			ref := fmt.Sprintf("%s/%s", env.Registry.Address, localName)
			reportDir := t.TempDir()
			reportPath := filepath.Join(reportDir, "report.json")

			t.Logf("Scanning original image %s:%s", ref, img.Tag)
			helpers.Trivy(t).
				WithOutput(reportPath).
				WithIgnoreFile(ignoreFile).
				Scan(fmt.Sprintf("%s:%s", ref, img.Tag))

			tagPatched := img.Tag + "-patched"
			patchedRef := fmt.Sprintf("%s:%s", ref, tagPatched)

			t.Log("Patching single-architecture image")
			helpers.Copa(t, env).Patch(fmt.Sprintf("%s:%s", ref, img.Tag), tagPatched, reportDir, img.IgnoreErrors, false).Run()

			t.Logf("Scanning patched image %s", patchedRef)
			helpers.Trivy(t).
				WithIgnoreFile(ignoreFile).
				WithExitCode(0).
				Scan(patchedRef)
		})
	}
}
