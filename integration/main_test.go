package integration

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/project-copacetic/copacetic/test/helpers"
	"github.com/project-copacetic/copacetic/test/testenv"
	"github.com/stretchr/testify/require"
)

type TestImage struct {
	Tag           string   `json:"tag"`
	Description   string   `json:"description"`
	IgnoreErrors  bool     `json:"ignoreErrors"`
	Image         string   `json:"image,omitempty"`
	OriginalImage string   `json:"originalImage,omitempty"`
	Digest        string   `json:"digest,omitempty"`
	LocalName     string   `json:"localName,omitempty"`
	LocalImage    string   `json:"localImage,omitempty"`
	Push          bool     `json:"push"`
	Platforms     []string `json:"platforms,omitempty"`
}

var env *testenv.Env

func TestMain(m *testing.M) {
	log.Println("Building copa binary for integration tests...")
	projectRoot := ".."
	binaryPath := filepath.Join(projectRoot, "bin/copa")

	if err := os.MkdirAll(filepath.Dir(binaryPath), 0755); err != nil {
		log.Fatalf("Failed to create bin directory: %v", err)
	}

	buildCmd := exec.Command("go", "build", "-o", binaryPath, projectRoot)
	if output, err := buildCmd.CombinedOutput(); err != nil {
		log.Fatalf("Failed to build copa binary: %v\nOutput:\n%s", err, string(output))
	}
	log.Println("Copa binary built successfully.")

	t := &testing.T{}
	env = testenv.New(t)
	defer env.Teardown()

	log.Println("Preloading test images into the local test registry...")
	preloadAllImages(t)
	log.Println("Test images preloaded successfully.")

	os.Exit(m.Run())
}

func preloadAllImages(t *testing.T) {
	t.Helper()
	preloadImagesFromFile(t, "singlearch/fixtures/test-images.json")
	preloadImagesFromFile(t, "multiarch/fixtures/test-images.json")
}

func preloadImagesFromFile(t *testing.T, fixturePath string) {
	t.Helper()
	fixtureBytes, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	var images []TestImage
	err = json.Unmarshal(fixtureBytes, &images)
	require.NoError(t, err, "failed to unmarshal %s", fixturePath)

	for _, img := range images {
		var srcRef string
		if img.Image != "" {
			srcRef = img.Image
		} else {
			srcRef = img.OriginalImage
		}

		srcRef = fmt.Sprintf("%s:%s", srcRef, img.Tag)
		if img.Digest != "" {
			srcRef = fmt.Sprintf("%s@%s", srcRef, img.Digest)
		}

		var dstName string
		if strings.Contains(img.LocalImage, "/") {
			parts := strings.Split(img.LocalImage, "/")
			dstName = parts[len(parts)-1]
		} else if img.LocalName != "" {
			dstName = img.LocalName
		} else {
			parts := strings.Split(srcRef, "/")
			dstName = "test/" + parts[len(parts)-1]
		}
		dstName, _, _ = strings.Cut(dstName, ":")
		dstName, _, _ = strings.Cut(dstName, "@")

		dstRef := fmt.Sprintf("%s/%s:%s", env.Registry.Address, dstName, img.Tag)

		t.Logf("Copying %s to %s", srcRef, dstRef)
		helpers.OrasCopy(t, srcRef, dstRef)
	}
}
