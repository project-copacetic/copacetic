package patch

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	buildkitclient "github.com/moby/buildkit/client"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type trackingReadCloser struct {
	closed bool
}

type testBuildkitBuildClient struct {
	gateway gwclient.Client
}

//nolint:gocritic // The BuildKit client API requires SolveOpt by value.
func (c *testBuildkitBuildClient) Build(
	ctx context.Context,
	_ buildkitclient.SolveOpt,
	_ string,
	buildFunc gwclient.BuildFunc,
	_ chan *buildkitclient.SolveStatus,
) (*buildkitclient.SolveResponse, error) {
	_, err := buildFunc(ctx, c.gateway)
	return &buildkitclient.SolveResponse{}, err
}

func (t *trackingReadCloser) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (t *trackingReadCloser) Close() error {
	t.closed = true
	return nil
}

func TestPatchSingleArchImageRejectsInvalidReference(t *testing.T) {
	t.Parallel()

	result, err := patchSingleArchImage(context.Background(), &types.Options{Image: "not a valid reference"}, types.PatchPlatform{}, false, nil)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to parse reference")
}

func TestValidatePlatformEmulationAllowsHostPlatform(t *testing.T) {
	t.Parallel()

	// validatePlatformEmulation forces the host OS to "linux" before comparing
	// against the target, so the cross-platform happy path is always
	// linux/<host-arch>, regardless of the developer's actual OS.
	host := platforms.Normalize(platforms.DefaultSpec())
	target := types.PatchPlatform{Platform: v1.Platform{OS: LINUX, Architecture: host.Architecture, Variant: host.Variant}}

	err := validatePlatformEmulation(target)

	assert.NoError(t, err)
}

func TestSetupWorkingFolderCreatesTemporaryDirectory(t *testing.T) {
	originalLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	t.Cleanup(func() { log.SetLevel(originalLevel) })

	workingFolder, cleanup, err := setupWorkingFolder("")
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	t.Cleanup(cleanup)

	info, err := os.Stat(workingFolder)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0o744), info.Mode().Perm())

	cleanup()
	_, err = os.Stat(workingFolder)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestSetupWorkingFolderHonorsExistingDirectoryWithoutRemovingIt(t *testing.T) {
	originalLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	t.Cleanup(func() { log.SetLevel(originalLevel) })

	workingFolder := t.TempDir()
	require.NoError(t, os.Chmod(workingFolder, 0o744))

	resolvedFolder, cleanup, err := setupWorkingFolder(workingFolder)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	assert.Equal(t, workingFolder, resolvedFolder)

	cleanup()
	info, err := os.Stat(workingFolder)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0o744), info.Mode().Perm())
}

func TestSetupWorkingFolderCreatesExplicitDirectoryAndCleanupRemovesIt(t *testing.T) {
	originalLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel)
	t.Cleanup(func() { log.SetLevel(originalLevel) })

	workingFolder := filepath.Join(t.TempDir(), "new-working-folder")

	resolvedFolder, cleanup, err := setupWorkingFolder(workingFolder)
	require.NoError(t, err)
	require.NotNil(t, cleanup)
	t.Cleanup(cleanup)
	assert.Equal(t, workingFolder, resolvedFolder)

	info, err := os.Stat(workingFolder)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0o744), info.Mode().Perm())

	cleanup()
	_, err = os.Stat(workingFolder)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestSetupWorkingFolderReturnsTempDirCreationError(t *testing.T) {
	tmpRootFile := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(tmpRootFile, []byte("x"), 0o600))
	t.Setenv("TMPDIR", tmpRootFile)

	workingFolder, cleanup, err := setupWorkingFolder("")

	require.Error(t, err)
	assert.Empty(t, workingFolder)
	assert.Nil(t, cleanup)
}

func TestSetupWorkingFolderReturnsEnsurePathErrors(t *testing.T) {
	tests := []struct {
		name      string
		setupPath func(t *testing.T) string
		errIs     error
	}{
		{
			name: "existing file is rejected",
			setupPath: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "working-folder")
				require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
				return path
			},
			errIs: fs.ErrExist,
		},
		{
			name: "existing directory with wrong permissions is rejected",
			setupPath: func(t *testing.T) string {
				path := filepath.Join(t.TempDir(), "working-folder")
				require.NoError(t, os.Mkdir(path, 0o755))
				return path
			},
			errIs: fs.ErrPermission,
		},
		{
			name: "invalid parent path is returned",
			setupPath: func(t *testing.T) string {
				parent := filepath.Join(t.TempDir(), "file-parent")
				require.NoError(t, os.WriteFile(parent, []byte("x"), 0o600))
				return filepath.Join(parent, "child")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workingFolder, cleanup, err := setupWorkingFolder(tt.setupPath(t))

			require.Error(t, err)
			assert.Empty(t, workingFolder)
			assert.Nil(t, cleanup)
			if tt.errIs != nil {
				assert.ErrorIs(t, err, tt.errIs)
			}
		})
	}
}

func TestResolveImageReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		imageRef string
		expected string
	}{
		{
			name:     "name only defaults to latest",
			imageRef: "docker.io/library/alpine",
			expected: "docker.io/library/alpine:latest",
		},
		{
			name:     "tagged reference is preserved",
			imageRef: "docker.io/library/alpine:3.20",
			expected: "docker.io/library/alpine:3.20",
		},
		{
			name:     "digest reference is preserved",
			imageRef: "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expected: "docker.io/library/alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			imageName, err := reference.ParseNormalizedNamed(tt.imageRef)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, resolveImageReference(imageName))
		})
	}
}

func TestDetermineLoaderType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		loader   string
		bkAddr   string
		expected string
	}{
		{
			name:     "explicit loader wins over auto detection",
			loader:   imageloader.Podman,
			bkAddr:   "docker-container://builder0",
			expected: imageloader.Podman,
		},
		{
			name:     "auto detects docker from buildkit address",
			bkAddr:   "docker-container://builder0",
			expected: imageloader.Docker,
		},
		{
			name:     "unknown address leaves loader empty",
			bkAddr:   "tcp://buildkit.example:1234",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, determineLoaderType(tt.loader, tt.bkAddr))
		})
	}
}

func TestLoadImageToRuntimeReturnsLoaderCreationErrors(t *testing.T) {
	t.Parallel()

	t.Run("pipe reader propagates loader creation error to writer", func(t *testing.T) {
		t.Parallel()

		reader, writer := io.Pipe()

		err := loadImageToRuntime(context.Background(), reader, "example.com/test:patched", "definitely-not-a-runtime")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create loader")
		assert.Contains(t, err.Error(), "unknown loader \"definitely-not-a-runtime\"")

		_, writeErr := writer.Write([]byte("data"))
		require.Error(t, writeErr)
		assert.EqualError(t, writeErr, err.Error())
		assert.NoError(t, writer.Close())
	})

	t.Run("generic read closer is closed on error", func(t *testing.T) {
		t.Parallel()

		tracker := &trackingReadCloser{}

		err := loadImageToRuntime(context.Background(), tracker, "example.com/test:patched", "definitely-not-a-runtime")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create loader")
		assert.Contains(t, err.Error(), "unknown loader \"definitely-not-a-runtime\"")
		assert.True(t, tracker.closed)
	})
}

func TestCreatePatchResultWithStatesRejectsInvalidPatchedImageName(t *testing.T) {
	t.Parallel()

	imageName, err := reference.ParseNormalizedNamed("docker.io/library/alpine:3.20")
	require.NoError(t, err)

	result, err := createPatchResultWithStates(
		imageName,
		"Not A Valid Image Reference",
		&types.PatchPlatform{Platform: v1.Platform{OS: LINUX, Architecture: "amd64"}},
		nil,
		imageloader.Docker,
		nil,
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to parse patched image name")
}

func TestShouldIncludeUpdateTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                 string
		pkgTypes             []string
		expectOSUpdates      bool
		expectLibraryUpdates bool
	}{
		{
			name:                 "os only",
			pkgTypes:             []string{utils.PkgTypeOS},
			expectOSUpdates:      true,
			expectLibraryUpdates: false,
		},
		{
			name:                 "library only",
			pkgTypes:             []string{utils.PkgTypeLibrary},
			expectOSUpdates:      false,
			expectLibraryUpdates: true,
		},
		{
			name:                 "mixed package types",
			pkgTypes:             []string{utils.PkgTypeOS, utils.PkgTypeLibrary},
			expectOSUpdates:      true,
			expectLibraryUpdates: true,
		},
		{
			name:                 "empty package types",
			pkgTypes:             nil,
			expectOSUpdates:      false,
			expectLibraryUpdates: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expectOSUpdates, shouldIncludeOSUpdates(tt.pkgTypes))
			assert.Equal(t, tt.expectLibraryUpdates, shouldIncludeLibraryUpdates(tt.pkgTypes))
		})
	}
}

func TestPatchSingleArchImageReturnsReportParseError(t *testing.T) {
	t.Parallel()

	result, err := patchSingleArchImage(
		context.Background(),
		&types.Options{
			Image:             "docker.io/library/alpine:3.20",
			Report:            filepath.Join("..", "report", "testdata", "invalid.json"),
			Scanner:           "trivy",
			PkgTypes:          utils.PkgTypeOS,
			LibraryPatchLevel: utils.PatchTypePatch,
		},
		types.PatchPlatform{},
		false,
		nil,
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "is not a supported scan report format")
}

func TestValidateReportPlatform(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		updates       *unversioned.UpdateManifest
		target        v1.Platform
		expectedError string
	}{
		{
			name:   "nil report manifest",
			target: v1.Platform{OS: LINUX, Architecture: "amd64"},
		},
		{
			name: "missing report architecture",
			updates: &unversioned.UpdateManifest{Metadata: unversioned.Metadata{
				Config: unversioned.Config{Variant: "v6"},
			}},
			target: v1.Platform{OS: LINUX, Architecture: "arm", Variant: "v7"},
		},
		{
			name: "normalizes architecture alias",
			updates: &unversioned.UpdateManifest{Metadata: unversioned.Metadata{
				Config: unversioned.Config{Arch: "x86_64"},
			}},
			target: v1.Platform{OS: LINUX, Architecture: "amd64"},
		},
		{
			name: "normalizes arm64 v8",
			updates: &unversioned.UpdateManifest{Metadata: unversioned.Metadata{
				Config: unversioned.Config{Arch: "aarch64", Variant: "v8"},
			}},
			target: v1.Platform{OS: LINUX, Architecture: "arm64"},
		},
		{
			name: "normalizes arm variant",
			updates: &unversioned.UpdateManifest{Metadata: unversioned.Metadata{
				Config: unversioned.Config{Arch: "arm", Variant: "7"},
			}},
			target: v1.Platform{OS: LINUX, Architecture: "arm", Variant: "v7"},
		},
		{
			name: "rejects architecture mismatch",
			updates: &unversioned.UpdateManifest{Metadata: unversioned.Metadata{
				Config: unversioned.Config{Arch: "amd64"},
			}},
			target:        v1.Platform{OS: LINUX, Architecture: "arm64"},
			expectedError: "scan report platform linux/amd64 does not match target platform linux/arm64",
		},
		{
			name: "rejects variant mismatch",
			updates: &unversioned.UpdateManifest{Metadata: unversioned.Metadata{
				Config: unversioned.Config{Arch: "arm", Variant: "v6"},
			}},
			target:        v1.Platform{OS: LINUX, Architecture: "arm", Variant: "v7"},
			expectedError: "scan report platform linux/arm/v6 does not match target platform linux/arm/v7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateReportPlatform(tt.updates, &types.PatchPlatform{Platform: tt.target})
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.expectedError)
				assert.ErrorContains(t, err, "generate the report for the selected platform")
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestPatchSingleArchImageRejectsReportPlatformMismatchBeforeBuildKit(t *testing.T) {
	originalBKNewClient := bkNewClient
	buildkitCalled := false
	bkNewClient = func(context.Context, buildkit.Opts) (*buildkitclient.Client, error) {
		buildkitCalled = true
		return nil, errors.New("buildkit must not be called for a report platform mismatch")
	}
	t.Cleanup(func() { bkNewClient = originalBKNewClient })

	result, err := patchSingleArchImage(
		context.Background(),
		&types.Options{
			Image:             "docker.io/library/alpine:3.20",
			Report:            filepath.Join("..", "report", "testdata", "trivy_valid.json"),
			Scanner:           "trivy",
			PkgTypes:          utils.PkgTypeOS,
			LibraryPatchLevel: utils.PatchTypePatch,
		},
		types.PatchPlatform{Platform: v1.Platform{OS: LINUX, Architecture: "arm64"}},
		false,
		nil,
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.ErrorContains(t, err, "scan report platform linux/amd64 does not match target platform linux/arm64")
	assert.False(t, buildkitCalled, "report platform validation must happen before creating a BuildKit client")
}

func TestPatchSingleArchImageReturnsNoUpdatesFoundAfterFiltering(t *testing.T) {
	t.Parallel()

	result, err := patchSingleArchImage(
		context.Background(),
		&types.Options{
			Image:             "localhost:65535/test-image:latest",
			Report:            filepath.Join("..", "report", "testdata", "trivy_python_venv.json"),
			Scanner:           "trivy",
			PkgTypes:          utils.PkgTypeOS,
			LibraryPatchLevel: utils.PatchTypePatch,
		},
		types.PatchPlatform{Platform: v1.Platform{OS: LINUX, Architecture: "amd64"}},
		false,
		nil,
	)

	assert.ErrorIs(t, err, types.ErrNoUpdatesFound)
	require.NotNil(t, result)
	assert.Equal(t, "localhost:65535/test-image:latest", result.OriginalRef.String())
	assert.Equal(t, result.OriginalRef.String(), result.PatchedRef.String())
}

func TestEmptyReportPreflightUsesNativeSuppliedPatchedImage(t *testing.T) {
	gateway := &recordedBaseNativePatchedGateway{}
	bkClient := &testBuildkitBuildClient{gateway: gateway}
	platform := &v1.Platform{OS: LINUX, Architecture: "amd64"}

	err := rejectTargetedNativeChiselPatch(
		t.Context(),
		bkClient,
		testNativeSuppliedImage,
		platform,
	)

	require.ErrorIs(t, err, errNativeChiselTargetedPatch)
	assert.Equal(t, testNativeSuppliedImage, gateway.inspectedImage)
}

func TestAugmentPatchedDescriptorIncludesManagerAnnotations(t *testing.T) {
	originalDescriptor := &v1.Descriptor{
		Annotations: map[string]string{
			"runtime": "preserved",
		},
	}
	originalAnnotations := map[string]string{
		"org.opencontainers.image.source": "https://example.com/source",
		pkgmgr.ChiselReleaseAnnotation:    "stale-release",
	}
	managerAnnotations := map[string]string{
		pkgmgr.ChiselReleaseAnnotation: "ubuntu-24.04",
		pkgmgr.ChiselVersionAnnotation: "v1.4.2",
	}

	augmented := augmentPatchedDescriptor(originalDescriptor, originalAnnotations, managerAnnotations)
	require.NotNil(t, augmented)
	assert.Equal(t, "preserved", augmented.Annotations["runtime"])
	assert.Equal(t, "https://example.com/source", augmented.Annotations["org.opencontainers.image.source"])
	assert.Equal(t, "ubuntu-24.04", augmented.Annotations[pkgmgr.ChiselReleaseAnnotation])
	assert.Equal(t, "v1.4.2", augmented.Annotations[pkgmgr.ChiselVersionAnnotation])
	assert.NotEmpty(t, augmented.Annotations["org.opencontainers.image.created"])
	assert.NotEmpty(t, augmented.Annotations[copaAnnotationKeyPrefix+".image.patched"])

	assert.Equal(t, map[string]string{"runtime": "preserved"}, originalDescriptor.Annotations, "the source descriptor must not be mutated")
}
