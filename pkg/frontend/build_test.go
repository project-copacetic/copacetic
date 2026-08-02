package frontend

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	copabuildkit "github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	fstypes "github.com/tonistiigi/fsutil/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	osLinux             = "linux"
	frontendReleaseRoot = "release"
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

	metadata, err := frontendResultMetadata(configData, nil, &platform, annotations)
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

func TestFrontendResultMetadataUsesPatchedConfigWhenPresent(t *testing.T) {
	baseConfig, err := json.Marshal(ocispecs.Image{
		Config: ocispecs.ImageConfig{
			User:       "base-user",
			Entrypoint: []string{"/base-entrypoint"},
			Cmd:        []string{"base-command"},
			Env:        []string{"BASE_ONLY=true"},
			WorkingDir: "/base",
			Labels:     map[string]string{"source": "base"},
		},
	})
	require.NoError(t, err)
	patchedConfig, err := json.Marshal(ocispecs.Image{
		Config: ocispecs.ImageConfig{
			User:       "1001:1001",
			Entrypoint: []string{"/app/entrypoint"},
			Cmd:        []string{"serve", "--production"},
			Env:        []string{"APP_ENV=production", "PORT=8080"},
			WorkingDir: "/app",
			Labels:     map[string]string{"source": "supplied-image"},
		},
	})
	require.NoError(t, err)
	platform := ocispecs.Platform{OS: osLinux, Architecture: "amd64"}

	metadata, err := frontendResultMetadata(
		baseConfig,
		patchedConfig,
		&platform,
		map[string]string{pkgmgr.ChiselReleaseAnnotation: "ubuntu-24.04"},
	)
	require.NoError(t, err)

	var image ocispecs.Image
	require.NoError(t, json.Unmarshal(metadata[exptypes.ExporterImageConfigKey+"/linux/amd64"], &image))
	assert.Equal(t, "1001:1001", image.Config.User)
	assert.Equal(t, []string{"/app/entrypoint"}, image.Config.Entrypoint)
	assert.Equal(t, []string{"serve", "--production"}, image.Config.Cmd)
	assert.Equal(t, []string{"APP_ENV=production", "PORT=8080"}, image.Config.Env)
	assert.Equal(t, "/app", image.Config.WorkingDir)
	assert.Equal(t, "supplied-image", image.Config.Labels["source"])
	assert.Equal(t, "ubuntu-24.04", image.Config.Labels[pkgmgr.ChiselReleaseAnnotation])
}

type frontendMetadataTestClient struct {
	gwclient.Client
	result *gwclient.Result
}

func (c *frontendMetadataTestClient) Solve(context.Context, gwclient.SolveRequest) (*gwclient.Result, error) {
	return c.result, nil
}

func (c *frontendMetadataTestClient) ResolveImageConfig(
	_ context.Context,
	ref string,
	_ sourceresolver.Opt,
) (string, digest.Digest, []byte, error) {
	config := []byte(`{"architecture":"amd64","os":"linux","config":{"labels":{}}}`)
	return ref, digest.FromString(ref), config, nil
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
	statErr       error
	readData      []byte
	readErr       error
	statCalls     int
	readFileCalls int
}

func (r *frontendStatePathReference) StatFile(_ context.Context, req gwclient.StatRequest) (*fstypes.Stat, error) {
	r.statCalls++
	if req.Path == pkgmgr.NativeChiselManifestPath && r.statErr != nil {
		return nil, r.statErr
	}
	return &fstypes.Stat{Path: req.Path, Size: int64(len(r.readData))}, nil
}

func (r *frontendStatePathReference) ReadFile(context.Context, gwclient.ReadRequest) ([]byte, error) {
	r.readFileCalls++
	return r.readData, r.readErr
}

func TestBuildPatchedImageRejectsNativeChiselReportBeforeSetup(t *testing.T) {
	for _, ignoreErrors := range []bool{false, true} {
		t.Run(fmt.Sprintf("ignore-errors=%t", ignoreErrors), func(t *testing.T) {
			reference := &frontendStatePathReference{}
			result := gwclient.NewResult()
			result.SetRef(reference)
			frontend := &Frontend{client: &frontendMetadataTestClient{result: result}}

			_, err := frontend.buildPatchedImage(t.Context(), &types.Options{
				Image:       "example.com/community/native-chisel:latest",
				Report:      filepath.Join(t.TempDir(), "not-parsed.json"),
				IgnoreError: ignoreErrors,
			}, nil)

			require.EqualError(t, err, pkgmgr.NativeChiselTargetedPatchError)
			assert.Equal(t, 1, reference.statCalls)
			assert.Zero(t, reference.readFileCalls, "/etc/os-release must not be read before rejecting targeted native patching")
		})
	}
}

func TestBuildPatchedImageReportPreservesNonNativeSetup(t *testing.T) {
	reference := &frontendStatePathReference{
		statErr:  status.Error(codes.NotFound, "missing manifest"),
		readData: []byte("ID=alpine\nVERSION_ID=3.23\n"),
	}
	result := gwclient.NewResult()
	result.SetRef(reference)
	frontend := &Frontend{client: &frontendMetadataTestClient{result: result}}
	reportPath := filepath.Join(t.TempDir(), "missing-report.json")

	_, err := frontend.buildPatchedImage(t.Context(), &types.Options{
		Image:   "example.com/non-native:latest",
		Report:  reportPath,
		Scanner: "trivy",
	}, nil)

	require.ErrorContains(t, err, "failed to parse vulnerability report")
	assert.GreaterOrEqual(t, reference.statCalls, 1)
	assert.GreaterOrEqual(t, reference.readFileCalls, 1, "non-native images must continue through normal OS detection")
}

func TestExplicitNativeChiselOSInfo(t *testing.T) {
	localRelease := t.TempDir()
	tests := []struct {
		name        string
		override    string
		manifestErr error
		wantInfo    *common.OSInfo
	}{
		{
			name:     "named release",
			override: "ubuntu-24.04",
			wantInfo: &common.OSInfo{Type: utils.OSTypeUbuntu, Version: "24.04"},
		},
		{
			name:     "local release",
			override: localRelease,
			wantInfo: &common.OSInfo{Type: utils.OSTypeUbuntu},
		},
		{
			name:     "pinned Git release",
			override: "https://example.com/chisel-releases.git#v1.0.0",
			wantInfo: &common.OSInfo{Type: utils.OSTypeUbuntu},
		},
		{
			name:        "non-native image keeps normal OS detection",
			override:    "ubuntu-24.04",
			manifestErr: status.Error(codes.NotFound, "missing"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := gwclient.NewResult()
			result.SetRef(&frontendStatePathReference{statErr: test.manifestErr})
			client := &frontendMetadataTestClient{result: result}
			state := llb.Scratch()

			info, err := explicitNativeChiselOSInfo(t.Context(), client, &state, nil, test.override)
			require.NoError(t, err)
			assert.Equal(t, test.wantInfo, info)
		})
	}
}

func TestExplicitNativeChiselOSInfoRejectsInvalidNativeOverride(t *testing.T) {
	result := gwclient.NewResult()
	result.SetRef(&frontendStatePathReference{})
	client := &frontendMetadataTestClient{result: result}
	state := llb.Scratch()

	_, err := explicitNativeChiselOSInfo(t.Context(), client, &state, nil, "https://example.com/chisel-releases.git")
	require.ErrorContains(t, err, "must include a pinned commit or tag fragment")
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

type frontendInstallManager struct {
	state          *llb.State
	err            error
	calls          int
	gotManifest    *unversioned.UpdateManifest
	gotIgnoreError bool
}

func (m *frontendInstallManager) InstallUpdates(
	_ context.Context,
	manifest *unversioned.UpdateManifest,
	ignoreErrors bool,
) (*llb.State, []string, error) {
	m.calls++
	m.gotManifest = manifest
	m.gotIgnoreError = ignoreErrors
	return m.state, nil, m.err
}

func (m *frontendInstallManager) GetPackageType() string {
	return "dpkg"
}

func requireFrontendStateEqual(t *testing.T, expected, actual *llb.State) {
	t.Helper()

	expectedDefinition, err := expected.Marshal(t.Context())
	require.NoError(t, err)
	actualDefinition, err := actual.Marshal(t.Context())
	require.NoError(t, err)
	require.Equal(t, expectedDefinition.ToPB(), actualDefinition.ToPB())
}

func TestInstallFrontendUpdatesNativeNoUpdatesReturnsSuppliedState(t *testing.T) {
	baseState := llb.Scratch().File(llb.Mkfile("/base", 0o644, []byte("base")))
	suppliedState := llb.Scratch().File(llb.Mkfile("/supplied", 0o644, []byte("supplied")))

	for _, ignoreErrors := range []bool{false, true} {
		t.Run(fmt.Sprintf("ignore-errors=%t", ignoreErrors), func(t *testing.T) {
			manager := &frontendInstallManager{
				err: fmt.Errorf("native Chisel image is current: %w", types.ErrNoUpdatesFound),
			}
			config := &copabuildkit.Config{
				ImageState:        baseState,
				PatchedConfigData: []byte(`{"config":{}}`),
				PatchedImageState: suppliedState,
			}

			state, installed, err := installFrontendUpdates(t.Context(), config, manager, nil, ignoreErrors)

			require.NoError(t, err)
			assert.False(t, installed)
			assert.Equal(t, 1, manager.calls)
			assert.Nil(t, manager.gotManifest)
			assert.Equal(t, ignoreErrors, manager.gotIgnoreError)
			requireFrontendStateEqual(t, &suppliedState, &state)
		})
	}
}

func TestInstallFrontendUpdatesPreservesReportAndIgnoreErrorsBehavior(t *testing.T) {
	baseState := llb.Scratch().File(llb.Mkfile("/base", 0o644, []byte("base")))
	suppliedState := llb.Scratch().File(llb.Mkfile("/supplied", 0o644, []byte("supplied")))
	config := &copabuildkit.Config{
		ImageState:        baseState,
		PatchedConfigData: []byte(`{"config":{}}`),
		PatchedImageState: suppliedState,
	}

	t.Run("empty report returns supplied image without installing", func(t *testing.T) {
		manager := &frontendInstallManager{err: fmt.Errorf("must not be called")}
		emptyReport := &unversioned.UpdateManifest{}

		state, installed, err := installFrontendUpdates(t.Context(), config, manager, emptyReport, true)

		require.NoError(t, err)
		assert.False(t, installed)
		assert.Zero(t, manager.calls)
		requireFrontendStateEqual(t, &suppliedState, &state)
	})

	report := &unversioned.UpdateManifest{
		OSUpdates: unversioned.UpdatePackages{{Name: "libc6", FixedVersion: "1.2.3"}},
	}
	installErr := fmt.Errorf("repository unavailable")

	t.Run("unrelated install error remains fatal", func(t *testing.T) {
		manager := &frontendInstallManager{err: installErr}

		_, installed, err := installFrontendUpdates(t.Context(), config, manager, report, false)

		require.ErrorContains(t, err, "failed to install package updates: repository unavailable")
		assert.False(t, installed)
		assert.Equal(t, 1, manager.calls)
		assert.Same(t, report, manager.gotManifest)
		assert.False(t, manager.gotIgnoreError)
	})

	t.Run("ignore-errors returns supplied image for unrelated failures", func(t *testing.T) {
		manager := &frontendInstallManager{err: installErr}

		state, installed, err := installFrontendUpdates(t.Context(), config, manager, report, true)

		require.NoError(t, err)
		assert.False(t, installed)
		assert.Equal(t, 1, manager.calls)
		assert.Same(t, report, manager.gotManifest)
		assert.True(t, manager.gotIgnoreError)
		requireFrontendStateEqual(t, &suppliedState, &state)
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

type frontendReleaseContextReference struct {
	gwclient.Reference
	directories  map[string][]*fstypes.Stat
	files        map[string][]byte
	readRequests []gwclient.ReadRequest
}

func (r *frontendReleaseContextReference) ReadDir(_ context.Context, req gwclient.ReadDirRequest) ([]*fstypes.Stat, error) {
	entries, ok := r.directories[filepath.Clean(req.Path)]
	if !ok {
		return nil, fmt.Errorf("unexpected Chisel release directory read %q", req.Path)
	}
	return entries, nil
}

func (r *frontendReleaseContextReference) StatFile(_ context.Context, req gwclient.StatRequest) (*fstypes.Stat, error) {
	data, ok := r.files[filepath.Clean(req.Path)]
	if !ok {
		return nil, fmt.Errorf("unexpected Chisel release file stat %q", req.Path)
	}
	return &fstypes.Stat{Path: req.Path, Mode: uint32(0o644), Size: int64(len(data))}, nil
}

func (r *frontendReleaseContextReference) ReadFile(_ context.Context, req gwclient.ReadRequest) ([]byte, error) {
	data, ok := r.files[filepath.Clean(req.Filename)]
	if !ok {
		return nil, fmt.Errorf("unexpected Chisel release file read %q", req.Filename)
	}
	if req.Range == nil {
		r.readRequests = append(r.readRequests, req)
		return append([]byte(nil), data...), nil
	}

	requestRange := *req.Range
	req.Range = &requestRange
	r.readRequests = append(r.readRequests, req)
	if requestRange.Offset < 0 || requestRange.Length < 0 || requestRange.Offset > len(data) {
		return nil, fmt.Errorf("invalid Chisel release file range %+v for %q", requestRange, req.Filename)
	}
	end := min(requestRange.Offset+requestRange.Length, len(data))
	return append([]byte(nil), data[requestRange.Offset:end]...), nil
}

func TestExtractFrontendContextDirectoryReadsLargeFilesInChunks(t *testing.T) {
	const gatewayChunkSize = 8 << 20

	contents := make([]byte, gatewayChunkSize+17)
	for i := range contents {
		contents[i] = byte(i)
	}
	releaseFile := filepath.Join(frontendReleaseRoot, "large.yaml")
	reference := &frontendReleaseContextReference{
		directories: map[string][]*fstypes.Stat{
			frontendReleaseRoot: {
				{Path: releaseFile, Mode: uint32(0o644), Size: int64(len(contents))},
			},
		},
		files: map[string][]byte{releaseFile: contents},
	}
	destination := t.TempDir()
	fileCount := 0
	var totalBytes int64

	err := extractFrontendContextDirectory(t.Context(), reference, frontendReleaseRoot, destination, &fileCount, &totalBytes)
	require.NoError(t, err)
	assert.Equal(t, 1, fileCount)
	assert.Equal(t, int64(len(contents)), totalBytes)

	extracted, err := os.ReadFile(filepath.Join(destination, "large.yaml"))
	require.NoError(t, err)
	assert.Equal(t, contents, extracted)
	require.Len(t, reference.readRequests, 2)
	assert.Equal(t, &gwclient.FileRange{Offset: 0, Length: gatewayChunkSize}, reference.readRequests[0].Range)
	assert.Equal(t, &gwclient.FileRange{Offset: gatewayChunkSize, Length: len(contents) - gatewayChunkSize}, reference.readRequests[1].Range)
}

func TestExtractFrontendContextDirectoryPreservesSafeRelativeSymlinks(t *testing.T) {
	const releaseContents = "format: v1\n"
	reference := &frontendReleaseContextReference{
		directories: map[string][]*fstypes.Stat{
			frontendReleaseRoot: {
				{Path: "release/release.yaml", Mode: uint32(0o644), Size: int64(len(releaseContents))},
				{Path: "release/slices", Mode: uint32(os.ModeDir | 0o755)},
			},
			filepath.Join(frontendReleaseRoot, "slices"): {
				{
					Path:     "release/slices/current.yaml",
					Mode:     uint32(os.ModeSymlink | 0o777),
					Linkname: "../release.yaml",
				},
			},
		},
		files: map[string][]byte{
			filepath.Join(frontendReleaseRoot, "release.yaml"): []byte(releaseContents),
		},
	}
	destination := t.TempDir()
	fileCount := 0
	var totalBytes int64

	err := extractFrontendContextDirectory(t.Context(), reference, frontendReleaseRoot, destination, &fileCount, &totalBytes)
	require.NoError(t, err)
	assert.Equal(t, 3, fileCount)
	assert.Equal(t, int64(len(releaseContents)), totalBytes)

	linkPath := filepath.Join(destination, "slices", "current.yaml")
	info, err := os.Lstat(linkPath)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink)
	target, err := os.Readlink(linkPath)
	require.NoError(t, err)
	assert.Equal(t, "../release.yaml", target)
	contents, err := os.ReadFile(linkPath)
	require.NoError(t, err)
	assert.Equal(t, releaseContents, string(contents))
}

func TestExtractFrontendContextDirectoryRejectsEscapeThroughInTreeSymlink(t *testing.T) {
	reference := &frontendReleaseContextReference{
		directories: map[string][]*fstypes.Stat{
			frontendReleaseRoot: {
				{Path: "release/pivot", Mode: uint32(os.ModeSymlink | 0o777), Linkname: "."},
				{Path: "release/bad", Mode: uint32(os.ModeSymlink | 0o777), Linkname: "pivot/../outside"},
			},
		},
	}
	parent := t.TempDir()
	destination := filepath.Join(parent, frontendReleaseRoot)
	require.NoError(t, os.Mkdir(destination, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(parent, "outside"), []byte("outside"), 0o600))
	fileCount := 0
	var totalBytes int64

	err := extractFrontendContextDirectory(t.Context(), reference, frontendReleaseRoot, destination, &fileCount, &totalBytes)
	require.ErrorContains(t, err, "does not resolve safely within the release directory")
}

func TestExtractFrontendContextDirectoryRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name        string
		mode        os.FileMode
		linkTarget  string
		errContains string
	}{
		{
			name:        "absolute symlink target",
			mode:        os.ModeSymlink | 0o777,
			linkTarget:  "/etc/passwd",
			errContains: "has an absolute target",
		},
		{
			name:        "escaping symlink target",
			mode:        os.ModeSymlink | 0o777,
			linkTarget:  "../outside",
			errContains: "escapes the release directory",
		},
		{
			name:        "empty symlink target",
			mode:        os.ModeSymlink | 0o777,
			errContains: "has an empty target",
		},
		{
			name:        "special file",
			mode:        os.ModeNamedPipe | 0o600,
			errContains: "unsupported non-regular entry",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reference := &frontendReleaseContextReference{
				directories: map[string][]*fstypes.Stat{
					frontendReleaseRoot: {
						{
							Path:     "release/unsafe",
							Mode:     uint32(test.mode),
							Linkname: test.linkTarget,
						},
					},
				},
			}
			fileCount := 0
			var totalBytes int64

			err := extractFrontendContextDirectory(t.Context(), reference, frontendReleaseRoot, t.TempDir(), &fileCount, &totalBytes)
			require.ErrorContains(t, err, test.errContains)
		})
	}
}

func TestExtractChiselReleaseFromContextRejectsUnsafePaths(t *testing.T) {
	_, err := extractChiselReleaseFromContext(t.Context(), nil, "/absolute/release")
	require.ErrorContains(t, err, "must be relative")

	_, err = extractChiselReleaseFromContext(t.Context(), nil, "../outside")
	require.ErrorContains(t, err, "escapes its BuildKit context")
}
