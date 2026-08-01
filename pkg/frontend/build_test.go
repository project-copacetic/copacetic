package frontend

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fstypes "github.com/tonistiigi/fsutil/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	osLinux = "linux"
)

// Note: buildPatchedImage tests are covered by e2e tests in test/e2e/frontend/
// since they require a real BuildKit gateway client and complex setup.
// This file tests helper functions that can be unit tested.

func TestEnsureTempDirCreatesMissingDir(t *testing.T) {
	// Simulate the FROM scratch frontend image where /tmp does not exist.
	// Point TMPDIR at a not-yet-created path under a real temp dir, then
	// verify ensureTempDir() materializes it so os.MkdirTemp("", ...) works.
	parent := t.TempDir()
	missing := filepath.Join(parent, "does-not-exist-yet")

	t.Setenv("TMPDIR", missing)

	// Sanity: the directory really is missing before we call ensureTempDir.
	_, err := os.Stat(missing)
	require.True(t, os.IsNotExist(err), "expected %s to not exist", missing)

	require.NoError(t, ensureTempDir(), "ensureTempDir should create missing TempDir")

	info, err := os.Stat(missing)
	require.NoError(t, err)
	require.True(t, info.IsDir(), "expected %s to be a directory", missing)

	// MkdirTemp("", ...) must now succeed against the freshly created dir.
	tmpDir, err := os.MkdirTemp("", "copa-frontend-report-")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)
	assert.True(t, strings.HasPrefix(tmpDir, missing), "tmp dir %s should be inside %s", tmpDir, missing)
}

func TestPlatformSpecificReportFilename(t *testing.T) {
	t.Run("AMD64 platform", func(t *testing.T) {
		// Test the platform-specific filename construction logic
		// This mimics the logic in buildPatchedImage
		osName := osLinux
		arch := "amd64"
		variant := ""

		platformFile := osName + "-" + arch
		if variant != "" {
			platformFile = platformFile + "-" + variant
		}
		platformFile += jsonExt

		assert.Equal(t, "linux-amd64.json", platformFile)
	})

	t.Run("ARM64 v8 platform with variant", func(t *testing.T) {
		osName := osLinux
		arch := "arm64"
		variant := "v8"

		platformFile := osName + "-" + arch
		if variant != "" {
			platformFile = platformFile + "-" + variant
		}
		platformFile += jsonExt

		assert.Equal(t, "linux-arm64-v8.json", platformFile)
	})

	t.Run("ARM v7 platform", func(t *testing.T) {
		osName := osLinux
		arch := "arm"
		variant := "v7"

		platformFile := osName + "-" + arch
		if variant != "" {
			platformFile = platformFile + "-" + variant
		}
		platformFile += jsonExt

		assert.Equal(t, "linux-arm-v7.json", platformFile)
	})
}

func TestReportDirectoryStructure(t *testing.T) {
	t.Run("Create directory with platform-specific reports", func(t *testing.T) {
		// Create temporary directory
		tmpDir := t.TempDir()

		// Create platform-specific report files
		platforms := []string{
			"linux-amd64.json",
			"linux-arm64.json",
			"linux-arm-v7.json",
		}

		for _, platform := range platforms {
			reportPath := filepath.Join(tmpDir, platform)
			err := os.WriteFile(reportPath, []byte(`{"vulnerabilities":[]}`), 0o600)
			require.NoError(t, err)

			// Verify file exists
			_, err = os.Stat(reportPath)
			assert.NoError(t, err)
		}

		// Verify directory exists
		fi, err := os.Stat(tmpDir)
		require.NoError(t, err)
		assert.True(t, fi.IsDir())

		// Read directory and verify files
		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)
		assert.Len(t, entries, 3)
	})

	t.Run("Platform-specific report file discovery", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create some platform-specific files
		testFiles := map[string]bool{
			"linux-amd64.json": true,  // Should be found
			"linux-arm64.json": true,  // Should be found
			"report.json":      false, // Generic report
			"other.txt":        false, // Non-JSON file
			"linux-amd64.txt":  false, // Wrong extension
		}

		for filename := range testFiles {
			err := os.WriteFile(filepath.Join(tmpDir, filename), []byte("test"), 0o600)
			require.NoError(t, err)
		}

		// Check directory for platform-specific JSON files
		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)

		platformFiles := 0
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == jsonExt {
				// Check if filename matches platform pattern (contains hyphen)
				name := entry.Name()
				baseName := name[:len(name)-len(filepath.Ext(name))]
				if filepath.Ext(name) == jsonExt && len(baseName) > 0 && filepath.Base(baseName) == baseName {
					// This is a potential platform-specific file if it contains a hyphen
					if testFiles[entry.Name()] {
						platformFiles++
					}
				}
			}
		}

		assert.Equal(t, 2, platformFiles)
	})
}

func TestReportFileValidation(t *testing.T) {
	t.Run("Valid single report file", func(t *testing.T) {
		tmpDir := t.TempDir()
		reportFile := filepath.Join(tmpDir, "report.json")

		// Write valid JSON
		validJSON := `{"vulnerabilities":[{"id":"CVE-2023-1234"}]}`
		err := os.WriteFile(reportFile, []byte(validJSON), 0o600)
		require.NoError(t, err)

		// Verify file exists and can be read
		data, err := os.ReadFile(reportFile)
		require.NoError(t, err)
		assert.Contains(t, string(data), "CVE-2023-1234")
	})

	t.Run("Empty report file", func(t *testing.T) {
		tmpDir := t.TempDir()
		reportFile := filepath.Join(tmpDir, "empty.json")

		// Write empty JSON
		err := os.WriteFile(reportFile, []byte(`{}`), 0o600)
		require.NoError(t, err)

		// Verify file exists
		_, err = os.Stat(reportFile)
		assert.NoError(t, err)
	})

	t.Run("Missing report file", func(t *testing.T) {
		tmpDir := t.TempDir()
		reportFile := filepath.Join(tmpDir, "nonexistent.json")

		// Verify file does not exist
		_, err := os.Stat(reportFile)
		assert.Error(t, err)
		assert.True(t, os.IsNotExist(err))
	})
}

func TestTempDirPatterns(t *testing.T) {
	t.Run("Single file temp dir pattern", func(t *testing.T) {
		// This tests the temp directory pattern used in extractReportFromContext
		tmpDir, err := os.MkdirTemp("", "copa-frontend-report-")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		assert.Contains(t, tmpDir, "copa-frontend-report-")

		// Verify we can write to it
		testFile := filepath.Join(tmpDir, "test.json")
		err = os.WriteFile(testFile, []byte("test"), 0o600)
		assert.NoError(t, err)
	})

	t.Run("Directory temp dir pattern", func(t *testing.T) {
		// This tests the temp directory pattern used for report directories
		tmpDir, err := os.MkdirTemp("", "copa-frontend-reports-")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		assert.Contains(t, tmpDir, "copa-frontend-reports-")

		// Verify we can create multiple files
		files := []string{"linux-amd64.json", "linux-arm64.json"}
		for _, file := range files {
			err = os.WriteFile(filepath.Join(tmpDir, file), []byte("test"), 0o600)
			assert.NoError(t, err)
		}
	})
}

func TestReportPathLogic(t *testing.T) {
	t.Run("Detect directory vs file", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create a directory
		subDir := filepath.Join(tmpDir, "reports")
		err := os.Mkdir(subDir, 0o755)
		require.NoError(t, err)

		// Create a file
		reportFile := filepath.Join(tmpDir, "report.json")
		err = os.WriteFile(reportFile, []byte("{}"), 0o600)
		require.NoError(t, err)

		// Test directory detection
		fi, err := os.Stat(subDir)
		require.NoError(t, err)
		assert.True(t, fi.IsDir())

		// Test file detection
		fi, err = os.Stat(reportFile)
		require.NoError(t, err)
		assert.False(t, fi.IsDir())
	})

	t.Run("Platform-specific file within directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create platform-specific files
		platforms := map[string]string{
			"linux-amd64.json": `{"platform":"amd64"}`,
			"linux-arm64.json": `{"platform":"arm64"}`,
		}

		for filename, content := range platforms {
			path := filepath.Join(tmpDir, filename)
			err := os.WriteFile(path, []byte(content), 0o600)
			require.NoError(t, err)
		}

		// Test looking for specific platform file
		targetPlatform := "linux-amd64.json"
		specificPath := filepath.Join(tmpDir, targetPlatform)

		_, err := os.Stat(specificPath)
		assert.NoError(t, err)

		// Test looking for non-existent platform
		nonExistentPath := filepath.Join(tmpDir, "linux-s390x.json")
		_, err = os.Stat(nonExistentPath)
		assert.Error(t, err)
		assert.True(t, os.IsNotExist(err))
	})
}

func TestJSONFileFiltering(t *testing.T) {
	t.Run("Filter only JSON files from directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Create mix of files
		files := map[string]string{
			"report1.json": "{}",
			"report2.json": "{}",
			"readme.md":    "# Readme",
			"config.yaml":  "key: value",
			"data.txt":     "text",
		}

		for filename, content := range files {
			err := os.WriteFile(filepath.Join(tmpDir, filename), []byte(content), 0o600)
			require.NoError(t, err)
		}

		// Read and filter JSON files
		entries, err := os.ReadDir(tmpDir)
		require.NoError(t, err)

		jsonFiles := []string{}
		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == jsonExt {
				jsonFiles = append(jsonFiles, entry.Name())
			}
		}

		assert.Len(t, jsonFiles, 2)
		assert.Contains(t, jsonFiles, "report1.json")
		assert.Contains(t, jsonFiles, "report2.json")
	})
}

func TestFrontendResultMetadataIncludesChiselAnnotations(t *testing.T) {
	configData, err := json.Marshal(ocispecs.Image{
		Config: ocispecs.ImageConfig{
			Labels: map[string]string{"existing": "preserved"},
		},
	})
	require.NoError(t, err)
	platform := ocispecs.Platform{OS: osLinux, Architecture: "amd64"}
	annotations := map[string]string{
		pkgmgr.ChiselReleaseAnnotation: "ubuntu-24.04",
		pkgmgr.ChiselVersionAnnotation: "v1.4.2",
	}

	metadata, err := frontendResultMetadata(configData, &platform, annotations)
	require.NoError(t, err)

	configKey := exptypes.ExporterImageConfigKey + "/linux/amd64"
	var image ocispecs.Image
	require.NoError(t, json.Unmarshal(metadata[configKey], &image))
	assert.Equal(t, "preserved", image.Config.Labels["existing"])
	assert.Equal(t, "ubuntu-24.04", image.Config.Labels[pkgmgr.ChiselReleaseAnnotation])
	assert.Equal(t, "v1.4.2", image.Config.Labels[pkgmgr.ChiselVersionAnnotation])
	assert.Equal(t, []byte("ubuntu-24.04"), metadata[exptypes.AnnotationManifestKey(&platform, pkgmgr.ChiselReleaseAnnotation)])
	assert.Equal(t, []byte("v1.4.2"), metadata[exptypes.AnnotationManifestKey(&platform, pkgmgr.ChiselVersionAnnotation)])
}

type frontendMetadataTestClient struct {
	gwclient.Client
	result *gwclient.Result
}

func (c *frontendMetadataTestClient) Solve(context.Context, gwclient.SolveRequest) (*gwclient.Result, error) {
	return c.result, nil
}

func TestResultMetadataClientDecoratesNextSolveAndRestoresClient(t *testing.T) {
	baseResult := gwclient.NewResult()
	baseClient := &frontendMetadataTestClient{result: baseResult}
	frontend := &Frontend{}
	decorator := &resultMetadataClient{
		Client: baseClient,
		owner:  frontend,
		metadata: map[string][]byte{
			exptypes.AnnotationManifestKey(nil, pkgmgr.ChiselReleaseAnnotation): []byte("ubuntu-24.04"),
		},
	}
	frontend.client = decorator

	result, err := frontend.client.Solve(context.Background(), gwclient.SolveRequest{})
	require.NoError(t, err)
	assert.Equal(t, []byte("ubuntu-24.04"), result.Metadata[exptypes.AnnotationManifestKey(nil, pkgmgr.ChiselReleaseAnnotation)])
	assert.Equal(t, baseClient, frontend.client)
}

func TestNativeChiselTargetedPatchErrorText(t *testing.T) {
	assert.Equal(t,
		"targeted patching of native Chisel manifests is not supported; omit --report to run a comprehensive Chisel update",
		pkgmgr.NativeChiselTargetedPatchError,
	)
}

type frontendStatePathReference struct {
	gwclient.Reference
	statErr error
}

func (r *frontendStatePathReference) StatFile(context.Context, gwclient.StatRequest) (*fstypes.Stat, error) {
	if r.statErr != nil {
		return nil, r.statErr
	}
	return &fstypes.Stat{Path: pkgmgr.NativeChiselManifestPath}, nil
}

func TestRejectTargetedNativeChiselState(t *testing.T) {
	t.Run("native manifest returns exact targeted error", func(t *testing.T) {
		result := gwclient.NewResult()
		result.SetRef(&frontendStatePathReference{})
		client := &frontendMetadataTestClient{result: result}
		state := llb.Scratch()

		err := rejectTargetedNativeChiselState(context.Background(), client, &state, nil)
		require.EqualError(t, err, pkgmgr.NativeChiselTargetedPatchError)
	})

	t.Run("missing manifest remains supported", func(t *testing.T) {
		result := gwclient.NewResult()
		result.SetRef(&frontendStatePathReference{statErr: status.Error(codes.NotFound, "missing")})
		client := &frontendMetadataTestClient{result: result}
		state := llb.Scratch()

		require.NoError(t, rejectTargetedNativeChiselState(context.Background(), client, &state, nil))
	})
}

func TestCopyFrontendResultMetadata(t *testing.T) {
	source := gwclient.NewResult()
	sourceValue := []byte("ubuntu-24.04")
	source.AddMeta(exptypes.AnnotationManifestKey(nil, pkgmgr.ChiselReleaseAnnotation), sourceValue)
	destination := gwclient.NewResult()

	copyFrontendResultMetadata(destination, source)
	sourceValue[0] = 'x'

	assert.Equal(t, []byte("ubuntu-24.04"), destination.Metadata[exptypes.AnnotationManifestKey(nil, pkgmgr.ChiselReleaseAnnotation)])
}

func TestExtractChiselReleaseFromContextRejectsUnsafePaths(t *testing.T) {
	_, err := extractChiselReleaseFromContext(t.Context(), nil, "/absolute/release")
	require.ErrorContains(t, err, "must be relative")

	_, err = extractChiselReleaseFromContext(t.Context(), nil, "../outside")
	require.ErrorContains(t, err, "escapes its BuildKit context")
}
