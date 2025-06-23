package integration

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
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
	OriginalImage string   `json:"originalImage"`
	LocalImage    string   `json:"localImage"`
	Tag           string   `json:"tag"`
	Distro        string   `json:"distro"`
	Description   string   `json:"description"`
	IgnoreErrors  bool     `json:"ignoreErrors"`
	Push          bool     `json:"push"`
	Platforms     []string `json:"platforms"`
}

func TestMultiArchPatch(t *testing.T) {
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

			dstName := strings.Split(img.LocalImage, "/")[1]
			ref := fmt.Sprintf("%s/%s", env.Registry.Address, dstName)
			reportDir := t.TempDir()

			t.Log("Creating scan reports for each platform")
			var wg sync.WaitGroup
			for _, platformStr := range img.Platforms {
				wg.Add(1)
				go func(platform string) {
					defer wg.Done()
					suffix := strings.ReplaceAll(platform, "/", "-")
					reportPath := filepath.Join(reportDir, "report-"+suffix+".json")

					t.Logf("Scanning original image %s:%s for platform %s", ref, img.Tag, platform)
					helpers.Trivy(t).
						WithPlatform(platform).
						WithOutput(reportPath).
						WithIgnoreFile(ignoreFile).
						Scan(fmt.Sprintf("%s:%s", ref, img.Tag))
				}(platformStr)
			}
			wg.Wait()

			tagPatched := img.Tag + "-patched"
			patchedRef := fmt.Sprintf("%s:%s", ref, tagPatched)

			t.Log("Patching multi-architecture image")
			helpers.Copa(t, env).Patch(fmt.Sprintf("%s:%s", ref, img.Tag), tagPatched, reportDir, img.IgnoreErrors, img.Push).Run()

			t.Log("Verifying patched images for each platform")
			wg = sync.WaitGroup{}
			for _, platformStr := range img.Platforms {
				wg.Add(1)
				go func(platform string) {
					defer wg.Done()
					t.Logf("Scanning patched image %s for platform %s", patchedRef, platform)
					helpers.Trivy(t).
						WithPlatform(platform).
						WithIgnoreFile(ignoreFile).
						WithExitCode(0).
						Scan(patchedRef)
				}(platformStr)
			}
			wg.Wait()
		})
	}
}
