package patch

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	fsutiltypes "github.com/tonistiigi/fsutil/types"

	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/mocks"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

const (
	testRecordedBaseImage   = "docker.io/example/non-native-base:latest"
	testNativeSuppliedImage = "docker.io/example/native-patched:latest"
	testImageSourcePrefix   = "docker-image://"
)

type recordedBaseNativePatchedGateway struct {
	gwclient.Client
	inspectedImage string
}

func (c *recordedBaseNativePatchedGateway) ResolveImageConfig(
	_ context.Context,
	ref string,
	_ sourceresolver.Opt,
) (string, digest.Digest, []byte, error) {
	var config []byte
	switch ref {
	case testNativeSuppliedImage:
		config = []byte(`{"config":{"labels":{"BaseImage":"` + testRecordedBaseImage + `"}}}`)
	case testRecordedBaseImage:
		config = []byte(`{"config":{"labels":{}}}`)
	default:
		return "", "", nil, errors.New("unexpected image config reference: " + ref)
	}
	return ref, digest.FromString(ref), config, nil
}

//nolint:gocritic // The gateway Client interface requires SolveRequest by value.
func (c *recordedBaseNativePatchedGateway) Solve(
	_ context.Context,
	req gwclient.SolveRequest,
) (*gwclient.Result, error) {
	for _, encodedOp := range req.Definition.Def {
		var op pb.Op
		if err := op.Unmarshal(encodedOp); err != nil {
			return nil, err
		}
		if source := op.GetSource(); source != nil {
			c.inspectedImage = strings.TrimPrefix(source.Identifier, testImageSourcePrefix)
		}
	}
	if c.inspectedImage == "" {
		return nil, errors.New("preflight state did not contain an image source")
	}

	result := gwclient.NewResult()
	result.SetRef(&nativeManifestTestReference{exists: c.inspectedImage == testNativeSuppliedImage})
	return result, nil
}

type nativeManifestTestReference struct {
	gwclient.Reference
	exists bool
}

func (r *nativeManifestTestReference) StatFile(
	_ context.Context,
	req gwclient.StatRequest,
) (*fsutiltypes.Stat, error) {
	if r.exists {
		return &fsutiltypes.Stat{Path: req.Path}, nil
	}
	return nil, &os.PathError{Op: "stat", Path: req.Path, Err: fs.ErrNotExist}
}

func solveRequestInspectsImageForPlatform(req *gwclient.SolveRequest, image string, platform *v1.Platform) bool {
	for _, encodedOp := range req.Definition.Def {
		var op pb.Op
		if err := op.Unmarshal(encodedOp); err != nil {
			return false
		}
		source := op.GetSource()
		if source == nil || source.Identifier != testImageSourcePrefix+image {
			continue
		}
		got := op.GetPlatform()
		return got != nil &&
			got.OS == platform.OS &&
			got.Architecture == platform.Architecture &&
			got.Variant == platform.Variant
	}
	return false
}

func TestImageConfigWithAnnotationsPreservesSuppliedImageConfig(t *testing.T) {
	baseConfig, err := json.Marshal(v1.Image{
		Config: v1.ImageConfig{
			User:       "base-user",
			Entrypoint: []string{"/base-entrypoint"},
			Cmd:        []string{"base-command"},
			Env:        []string{"BASE_ONLY=true"},
			WorkingDir: "/base",
			Labels:     map[string]string{"source": "base"},
		},
	})
	require.NoError(t, err)
	patchedConfig, err := json.Marshal(v1.Image{
		Config: v1.ImageConfig{
			User:       "1001:1001",
			Entrypoint: []string{"/app/entrypoint"},
			Cmd:        []string{"serve", "--production"},
			Env:        []string{"APP_ENV=production", "PORT=8080"},
			WorkingDir: "/app",
			Labels:     map[string]string{"source": "supplied-image"},
		},
	})
	require.NoError(t, err)

	config := &buildkit.Config{
		ConfigData:        baseConfig,
		PatchedConfigData: patchedConfig,
	}
	annotations := map[string]string{pkgmgr.ChiselReleaseAnnotation: "ubuntu-24.04"}

	resultConfig, err := imageConfigWithAnnotations(config, annotations)
	require.NoError(t, err)

	var image v1.Image
	require.NoError(t, json.Unmarshal(resultConfig, &image))
	assert.Equal(t, "1001:1001", image.Config.User)
	assert.Equal(t, []string{"/app/entrypoint"}, image.Config.Entrypoint)
	assert.Equal(t, []string{"serve", "--production"}, image.Config.Cmd)
	assert.Equal(t, []string{"APP_ENV=production", "PORT=8080"}, image.Config.Env)
	assert.Equal(t, "/app", image.Config.WorkingDir)
	assert.Equal(t, "supplied-image", image.Config.Labels["source"])
	assert.Equal(t, "ubuntu-24.04", image.Config.Labels[pkgmgr.ChiselReleaseAnnotation])
}

func TestImageConfigWithAnnotationsUsesBaseConfigForFirstPatch(t *testing.T) {
	baseConfig := []byte(`{"config":{"User":"base-user","Labels":{"source":"base"}}}`)
	resultConfig, err := imageConfigWithAnnotations(
		&buildkit.Config{ConfigData: baseConfig},
		map[string]string{pkgmgr.ChiselVersionAnnotation: "v1.4.2"},
	)
	require.NoError(t, err)

	var image v1.Image
	require.NoError(t, json.Unmarshal(resultConfig, &image))
	assert.Equal(t, "base-user", image.Config.User)
	assert.Equal(t, "base", image.Config.Labels["source"])
	assert.Equal(t, "v1.4.2", image.Config.Labels[pkgmgr.ChiselVersionAnnotation])
}

func TestImageConfigWithAnnotationsReplacesSourceLineageAtomically(t *testing.T) {
	staleDigest := digest.FromString("stale")
	configData := []byte(
		`{"config":{"Labels":{"org.opencontainers.image.base.name":"docker.io/library/stale:latest",` +
			`"org.opencontainers.image.base.digest":"` + staleDigest.String() + `","preserved":"value"}}}`,
	)

	omitted, err := imageConfigWithAnnotations(&buildkit.Config{ConfigData: configData}, nil)
	require.NoError(t, err)
	var omittedImage v1.Image
	require.NoError(t, json.Unmarshal(omitted, &omittedImage))
	assert.NotContains(t, omittedImage.Config.Labels, v1.AnnotationBaseImageName)
	assert.NotContains(t, omittedImage.Config.Labels, v1.AnnotationBaseImageDigest)
	assert.Equal(t, "value", omittedImage.Config.Labels["preserved"])

	lineage := &types.SourceLineage{
		Name:   "docker.io/library/alpine:3.20",
		Digest: digest.FromString("selected-base"),
	}
	replaced, err := imageConfigWithAnnotations(&buildkit.Config{ConfigData: configData}, sourceLineageAnnotations(lineage))
	require.NoError(t, err)
	var replacedImage v1.Image
	require.NoError(t, json.Unmarshal(replaced, &replacedImage))
	assert.Equal(t, lineage.Name, replacedImage.Config.Labels[v1.AnnotationBaseImageName])
	assert.Equal(t, lineage.Digest.String(), replacedImage.Config.Labels[v1.AnnotationBaseImageDigest])
}

func TestPreservedImageStateCarriesExecutionEnvironment(t *testing.T) {
	config := []byte(`{
		"architecture":"arm64",
		"os":"linux",
		"config":{
			"Env":["TEST_VALUE=present"],
			"WorkingDir":"/work",
			"Entrypoint":["/usr/bin/example"],
			"Cmd":["serve"]
		}
	}`)
	state := llb.Scratch()
	preserved, err := preservedImageState(&state, config)
	require.NoError(t, err)

	value, ok, err := preserved.GetEnv(t.Context(), "TEST_VALUE")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "present", value)
	dir, err := preserved.GetDir(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "/work", dir)
	platform, err := preserved.GetPlatform(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "linux", platform.OS)
	assert.Equal(t, "arm64", platform.Architecture)
}

func TestSetupPackageManagerUsesExplicitNativeChiselReleaseWithoutOSRelease(t *testing.T) {
	client := new(mocks.MockGWClient)
	ref := new(mocks.MockReference)
	result := gwclient.NewResult()
	result.SetRef(ref)
	client.On("Solve", mock.Anything, mock.Anything).Return(result, nil)
	ref.On("StatFile", mock.Anything, mock.MatchedBy(func(req gwclient.StatRequest) bool {
		return req.Path == pkgmgr.NativeChiselManifestPath
	})).Return(&fsutiltypes.Stat{Path: pkgmgr.NativeChiselManifestPath}, nil)

	config := &buildkit.Config{
		Client:     client,
		ImageState: llb.Scratch(),
		Platform:   &v1.Platform{OS: "linux", Architecture: "amd64"},
	}
	manager, err := setupPackageManager(t.Context(), client, config, &Options{
		WorkingFolder: t.TempDir(),
		ChiselRelease: "ubuntu-24.04",
	})
	require.NoError(t, err)
	assert.Equal(t, "deb", manager.GetPackageType())
	client.AssertExpectations(t)
	ref.AssertExpectations(t)
}

func TestSetupPackageManagerBoundsOSReleaseAndPreservesMissingError(t *testing.T) {
	missingErr := &os.PathError{Op: "stat", Path: "/etc/os-release", Err: fs.ErrNotExist}
	tests := []struct {
		name      string
		stat      *fsutiltypes.Stat
		statErr   error
		wantError string
		wantCause error
	}{
		{
			name:      "oversized",
			stat:      &fsutiltypes.Stat{Size: 1<<20 + 1},
			wantError: "maximum allowed size of 1048576 bytes",
		},
		{
			name:      "missing",
			statErr:   missingErr,
			wantError: "unable to extract /etc/os-release file from state",
			wantCause: fs.ErrNotExist,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := new(mocks.MockGWClient)
			ref := new(mocks.MockReference)
			result := gwclient.NewResult()
			result.SetRef(ref)
			client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()
			ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: "/etc/os-release"}).
				Return(test.stat, test.statErr).
				Once()

			config := &buildkit.Config{
				Client:     client,
				ImageState: llb.Scratch(),
				Platform:   &v1.Platform{OS: "linux", Architecture: "amd64"},
			}
			_, err := setupPackageManager(t.Context(), client, config, &Options{
				WorkingFolder: t.TempDir(),
			})
			require.ErrorContains(t, err, test.wantError)
			if test.wantCause != nil {
				require.ErrorIs(t, err, test.wantCause)
			}
			ref.AssertNotCalled(t, "ReadFile", mock.Anything, mock.Anything)
			client.AssertExpectations(t)
			ref.AssertExpectations(t)
		})
	}
}

func TestExplicitNativeChiselOSManifestInspection(t *testing.T) {
	statErr := errors.New("manifest stat denied")
	solveErr := errors.New("manifest solve failed")
	tests := []struct {
		name         string
		stat         *fsutiltypes.Stat
		statErr      error
		solveErr     error
		wantOSType   string
		wantVersion  string
		wantExplicit bool
		wantErr      string
		wantCause    error
	}{
		{
			name:         "present",
			stat:         &fsutiltypes.Stat{Path: pkgmgr.NativeChiselManifestPath},
			wantOSType:   utils.OSTypeUbuntu,
			wantVersion:  "24.04",
			wantExplicit: true,
		},
		{
			name: "missing",
			statErr: &os.PathError{
				Op:   "stat",
				Path: pkgmgr.NativeChiselManifestPath,
				Err:  fs.ErrNotExist,
			},
		},
		{
			name:    "directory is rejected",
			stat:    &fsutiltypes.Stat{Path: pkgmgr.NativeChiselManifestPath, Mode: uint32(os.ModeDir | 0o755)},
			wantErr: "not a regular file",
		},
		{
			name:      "stat failure",
			statErr:   statErr,
			wantErr:   "inspect target image for native Chisel metadata",
			wantCause: statErr,
		},
		{
			name:      "solve failure",
			solveErr:  solveErr,
			wantErr:   "inspect target image for native Chisel metadata",
			wantCause: solveErr,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const suppliedImage = "docker.io/example/supplied:latest"
			platform := v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
			config := &buildkit.Config{
				ImageState:        llb.Image("docker.io/example/base:latest"),
				PatchedConfigData: []byte(`{}`),
				PatchedImageState: llb.Image(suppliedImage),
				Platform:          &platform,
			}
			client := new(mocks.MockGWClient)
			result := gwclient.NewResult()
			var ref *mocks.MockReference
			if test.solveErr == nil {
				ref = new(mocks.MockReference)
				ref.On("StatFile", mock.Anything, mock.MatchedBy(func(req gwclient.StatRequest) bool {
					return req.Path == pkgmgr.NativeChiselManifestPath
				})).Return(test.stat, test.statErr).Once()
				result.SetRef(ref)
			}
			client.On("Solve", mock.Anything, mock.MatchedBy(func(req gwclient.SolveRequest) bool {
				return solveRequestInspectsImageForPlatform(&req, suppliedImage, &platform)
			})).Return(result, test.solveErr).Once()

			osType, version, explicit, err := explicitNativeChiselOS(
				t.Context(),
				client,
				config,
				"ubuntu-24.04",
			)

			if test.wantErr != "" {
				require.ErrorContains(t, err, test.wantErr)
				if test.wantCause != nil {
					require.ErrorIs(t, err, test.wantCause)
				}
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, test.wantOSType, osType)
			assert.Equal(t, test.wantVersion, version)
			assert.Equal(t, test.wantExplicit, explicit)
			client.AssertExpectations(t)
			if ref != nil {
				ref.AssertNotCalled(t, "ReadFile", mock.Anything, mock.Anything)
				ref.AssertExpectations(t)
			}
		})
	}
}

func TestExplicitNativeChiselOSUsesTargetVersionForExternalRelease(t *testing.T) {
	osRelease := []byte("NAME=Ubuntu\nID=ubuntu\nVERSION_ID=20.04\n")
	tests := []struct {
		name          string
		override      func(*testing.T) string
		osRelease     []byte
		osReleaseStat error
		wantVersion   string
	}{
		{
			name:        "local release",
			override:    func(t *testing.T) string { return t.TempDir() },
			osRelease:   osRelease,
			wantVersion: "20.04",
		},
		{
			name: "Git release",
			override: func(*testing.T) string {
				return "https://github.com/canonical/chisel-releases.git#ca7ad8113998470ff77231af799c363c4a48feca"
			},
			osRelease:   osRelease,
			wantVersion: "20.04",
		},
		{
			name:     "missing OS metadata is tolerated",
			override: func(t *testing.T) string { return t.TempDir() },
			osReleaseStat: &os.PathError{
				Op:   "stat",
				Path: "/etc/os-release",
				Err:  fs.ErrNotExist,
			},
		},
		{
			name:      "malformed OS metadata is tolerated for local release",
			override:  func(t *testing.T) string { return t.TempDir() },
			osRelease: []byte("NAME=Ubuntu\nVERSION_ID\n"),
		},
		{
			name: "missing VERSION_ID is tolerated for Git release",
			override: func(*testing.T) string {
				return "https://github.com/canonical/chisel-releases.git#ca7ad8113998470ff77231af799c363c4a48feca"
			},
			osRelease: []byte("NAME=Ubuntu\nID=ubuntu\n"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, ref := nativeChiselOSReleaseClient(t, test.osRelease, test.osReleaseStat)
			config := &buildkit.Config{
				Client:     client,
				ImageState: llb.Scratch(),
				Platform:   &v1.Platform{OS: "linux", Architecture: "amd64"},
			}

			osType, version, explicit, err := explicitNativeChiselOS(
				t.Context(),
				client,
				config,
				test.override(t),
			)

			require.NoError(t, err)
			assert.Equal(t, utils.OSTypeUbuntu, osType)
			assert.Equal(t, test.wantVersion, version)
			assert.True(t, explicit)
			client.AssertExpectations(t)
			ref.AssertExpectations(t)
		})
	}
}

func TestSetupPackageManagerExitOnEOLWithLocalChiselRelease(t *testing.T) {
	originalBaseURL := utils.GetEOLAPIBaseURL()
	defer utils.SetEOLAPIBaseURL(originalBaseURL)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/ubuntu/releases/20.04", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"result":{"isEol":true,"eolFrom":"2025-05-31","isMaintained":false}}`))
		assert.NoError(t, err)
	}))
	defer server.Close()
	utils.SetEOLAPIBaseURL(server.URL)

	client, ref := nativeChiselOSReleaseClient(
		t,
		[]byte("NAME=Ubuntu\nID=ubuntu\nVERSION_ID=20.04\n"),
		nil,
	)
	config := &buildkit.Config{
		Client:     client,
		ImageState: llb.Scratch(),
		Platform:   &v1.Platform{OS: "linux", Architecture: "amd64"},
	}

	_, err := setupPackageManager(t.Context(), client, config, &Options{
		WorkingFolder: t.TempDir(),
		ChiselRelease: t.TempDir(),
		ExitOnEOL:     true,
	})
	require.ErrorContains(t, err, "exiting due to EOL operating system: ubuntu 20.04")
	client.AssertExpectations(t)
	ref.AssertExpectations(t)
}

func nativeChiselOSReleaseClient(
	t *testing.T,
	osRelease []byte,
	osReleaseStatErr error,
) (*mocks.MockGWClient, *mocks.MockReference) {
	t.Helper()
	client := new(mocks.MockGWClient)
	ref := new(mocks.MockReference)
	result := gwclient.NewResult()
	result.SetRef(ref)
	client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Twice()
	ref.On("StatFile", mock.Anything, mock.MatchedBy(func(req gwclient.StatRequest) bool {
		return req.Path == pkgmgr.NativeChiselManifestPath
	})).Return(&fsutiltypes.Stat{Path: pkgmgr.NativeChiselManifestPath}, nil).Once()
	ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: "/etc/os-release"}).
		Return(&fsutiltypes.Stat{Path: "/etc/os-release", Size: int64(len(osRelease))}, osReleaseStatErr).
		Once()
	if osReleaseStatErr == nil {
		ref.On("ReadFile", mock.Anything, mock.MatchedBy(func(req gwclient.ReadRequest) bool {
			return req.Filename == "/etc/os-release"
		})).Return(osRelease, nil).Once()
	}
	return client, ref
}

func TestPreflightReportForNativeChiselRejectsEveryReportKind(t *testing.T) {
	tests := []struct {
		name    string
		updates *unversioned.UpdateManifest
	}{
		{
			name: "OS update report",
			updates: &unversioned.UpdateManifest{
				Metadata:  unversioned.Metadata{OS: unversioned.OS{Type: utils.OSTypeUbuntu, Version: "24.04"}},
				OSUpdates: unversioned.UpdatePackages{{Name: "libc6", FixedVersion: "2.39-0ubuntu8.6"}},
			},
		},
		{
			name: "language-only report",
			updates: &unversioned.UpdateManifest{
				LangUpdates: unversioned.LangUpdatePackages{{Name: "urllib3", FixedVersion: "2.5.0", Type: "python-pkg"}},
			},
		},
		{
			name: "non-DPKG report metadata",
			updates: &unversioned.UpdateManifest{
				Metadata:  unversioned.Metadata{OS: unversioned.OS{Type: utils.OSTypeAlpine, Version: "3.22"}},
				OSUpdates: unversioned.UpdatePackages{{Name: "musl", FixedVersion: "1.2.5-r10"}},
			},
		},
		{
			name:    "empty non-nil report",
			updates: &unversioned.UpdateManifest{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := new(mocks.MockGWClient)
			ref := new(mocks.MockReference)
			result := gwclient.NewResult()
			result.SetRef(ref)
			client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()
			ref.On("StatFile", mock.Anything, mock.MatchedBy(func(req gwclient.StatRequest) bool {
				return req.Path == pkgmgr.NativeChiselManifestPath
			})).Return(&fsutiltypes.Stat{Path: pkgmgr.NativeChiselManifestPath}, nil).Once()

			config := &buildkit.Config{ImageState: llb.Scratch()}
			platform := &types.PatchPlatform{Platform: v1.Platform{OS: "linux", Architecture: "amd64"}}

			err := preflightReportForNativeChisel(t.Context(), client, config, platform, test.updates)
			require.EqualError(t, err, pkgmgr.NativeChiselTargetedPatchError)
			client.AssertExpectations(t)
			ref.AssertExpectations(t)
		})
	}
}

func TestPreflightReportForNativeChiselUsesNativeSuppliedPatchedImage(t *testing.T) {
	client := &recordedBaseNativePatchedGateway{}
	platform := &types.PatchPlatform{Platform: v1.Platform{OS: "linux", Architecture: "amd64"}}
	config, err := buildkit.InitializeBuildkitConfig(
		t.Context(),
		client,
		testNativeSuppliedImage,
		&platform.Platform,
	)
	require.NoError(t, err)
	require.NotNil(t, config.PatchedConfigData)

	err = preflightReportForNativeChisel(t.Context(), client, config, platform, &unversioned.UpdateManifest{
		Metadata:  unversioned.Metadata{OS: unversioned.OS{Type: utils.OSTypeAlpine, Version: "3.22"}},
		OSUpdates: unversioned.UpdatePackages{{Name: "musl", FixedVersion: "1.2.5-r10"}},
	})

	require.EqualError(t, err, pkgmgr.NativeChiselTargetedPatchError)
	assert.Equal(t, testNativeSuppliedImage, client.inspectedImage)
}

func TestPreflightReportForNativeChiselFailsClosedOnInspectionError(t *testing.T) {
	inspectionErr := errors.New("manifest inspection denied")
	client := new(mocks.MockGWClient)
	ref := new(mocks.MockReference)
	result := gwclient.NewResult()
	result.SetRef(ref)
	client.On("Solve", mock.Anything, mock.Anything).Return(result, nil).Once()
	ref.On("StatFile", mock.Anything, mock.Anything).Return(&fsutiltypes.Stat{}, inspectionErr).Once()

	config := &buildkit.Config{ImageState: llb.Scratch()}
	platform := &types.PatchPlatform{Platform: v1.Platform{OS: "linux", Architecture: "amd64"}}
	err := preflightReportForNativeChisel(t.Context(), client, config, platform, &unversioned.UpdateManifest{})

	require.Error(t, err)
	assert.ErrorContains(t, err, "inspect target image for native Chisel metadata")
	assert.ErrorIs(t, err, inspectionErr)
	client.AssertExpectations(t)
	ref.AssertExpectations(t)
}

func TestPreflightReportForNativeChiselPreservesNoReportBehavior(t *testing.T) {
	client := new(mocks.MockGWClient)
	config := &buildkit.Config{ImageState: llb.Scratch()}
	platform := &types.PatchPlatform{Platform: v1.Platform{OS: "linux", Architecture: "amd64"}}

	require.NoError(t, preflightReportForNativeChisel(t.Context(), client, config, platform, nil))
	client.AssertNotCalled(t, "Solve", mock.Anything, mock.Anything)
}

func TestExitOnEOLFunctionality(t *testing.T) {
	// Test the ExitOnEOL functionality with mock EOL API
	originalBaseURL := utils.GetEOLAPIBaseURL()
	defer utils.SetEOLAPIBaseURL(originalBaseURL)

	tests := []struct {
		name        string
		exitOnEOL   bool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "ExitOnEOL disabled - should not exit",
			exitOnEOL:   false,
			expectError: false,
		},
		{
			name:        "ExitOnEOL enabled - should exit with error",
			exitOnEOL:   true,
			expectError: true,
			errorMsg:    "exiting due to EOL operating system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test validates the ExitOnEOL option is properly passed through
			// In a full integration test, we would set up a mock BuildKit client
			// For now, we verify the option is correctly configured

			opts := &Options{
				ExitOnEOL: tt.exitOnEOL,
			}

			if opts.ExitOnEOL != tt.exitOnEOL {
				t.Errorf("ExitOnEOL option not properly set: got %v, want %v", opts.ExitOnEOL, tt.exitOnEOL)
			}
		})
	}
}

// Test Options struct initialization and validation.
func TestOptions_Initialization(t *testing.T) {
	opts := &Options{
		ImageName: "test:latest",
		TargetPlatform: &types.PatchPlatform{
			Platform: v1.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
		},
		WorkingFolder: "/tmp/test",
		IgnoreError:   true,
	}

	assert.Equal(t, "test:latest", opts.ImageName)
	assert.Equal(t, "linux", opts.TargetPlatform.OS)
	assert.Equal(t, "amd64", opts.TargetPlatform.Architecture)
	assert.Equal(t, "/tmp/test", opts.WorkingFolder)
	assert.True(t, opts.IgnoreError)
}

// Test Options with Updates.
func TestOptions_WithUpdates(t *testing.T) {
	updates := &unversioned.UpdateManifest{
		OSUpdates: []unversioned.UpdatePackage{
			{
				Name:             "test-package",
				InstalledVersion: "1.0.0",
				FixedVersion:     "1.0.1",
			},
		},
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    utils.OSTypeDebian,
				Version: "11",
			},
		},
	}

	opts := &Options{
		ImageName: "test:latest",
		Updates:   updates,
	}

	assert.Equal(t, "test:latest", opts.ImageName)
	assert.NotNil(t, opts.Updates)
	assert.Len(t, opts.Updates.OSUpdates, 1)
	assert.Equal(t, "test-package", opts.Updates.OSUpdates[0].Name)
	assert.Equal(t, "debian", opts.Updates.Metadata.OS.Type)
}

// Test Options with error channel.
func TestOptions_WithErrorChannel(t *testing.T) {
	errorChannel := make(chan error, 10)

	opts := &Options{
		ImageName:    "test:latest",
		ErrorChannel: errorChannel,
	}

	assert.Equal(t, "test:latest", opts.ImageName)
	assert.NotNil(t, opts.ErrorChannel)
	assert.Equal(t, cap(errorChannel), cap(opts.ErrorChannel))
}

// Test Result struct initialization and validation.
func TestResult_Initialization(t *testing.T) {
	result := &Result{
		PackageType:      "deb",
		ErroredPackages:  []string{"pkg1", "pkg2"},
		ValidatedUpdates: []unversioned.UpdatePackage{{Name: "pkg3", FixedVersion: "1.0.1"}},
	}

	assert.Equal(t, "deb", result.PackageType)
	assert.Equal(t, []string{"pkg1", "pkg2"}, result.ErroredPackages)
	assert.NotNil(t, result.ValidatedUpdates)
	assert.Len(t, result.ValidatedUpdates, 1)
	assert.Equal(t, "pkg3", result.ValidatedUpdates[0].Name)
}

// Test Result with empty fields.
func TestResult_Empty(t *testing.T) {
	result := &Result{}

	assert.Empty(t, result.PackageType)
	assert.Nil(t, result.ErroredPackages)
	assert.Nil(t, result.Result)
	assert.Nil(t, result.ValidatedUpdates)
}

// Test Result with multiple validated updates.
func TestResult_MultipleValidatedUpdates(t *testing.T) {
	result := &Result{
		PackageType:      "rpm",
		ValidatedUpdates: []unversioned.UpdatePackage{{Name: "pkg1", FixedVersion: "1.0.1"}, {Name: "pkg2", FixedVersion: "2.0.1"}, {Name: "pkg3", FixedVersion: "3.0.1"}},
	}

	assert.Equal(t, "rpm", result.PackageType)
	assert.NotNil(t, result.ValidatedUpdates)
	assert.Len(t, result.ValidatedUpdates, 3)
	assert.Equal(t, "pkg1", result.ValidatedUpdates[0].Name)
	assert.Equal(t, "pkg2", result.ValidatedUpdates[1].Name)
	assert.Equal(t, "pkg3", result.ValidatedUpdates[2].Name)
}

// Test Context struct initialization.
func TestContext_Initialization(t *testing.T) {
	// Test with nil values
	patchCtx := &Context{}

	assert.Nil(t, patchCtx.Context)
	assert.Nil(t, patchCtx.Client)
}

// Test package types commonly used.
func TestResult_CommonPackageTypes(t *testing.T) {
	testCases := []struct {
		name        string
		packageType string
	}{
		{"Debian packages", "deb"},
		{"RPM packages", "rpm"},
		{"Alpine packages", "apk"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := &Result{
				PackageType: tc.packageType,
			}
			assert.Equal(t, tc.packageType, result.PackageType)
		})
	}
}

func TestEOLConfigurationIntegration(t *testing.T) {
	// Test URL configuration
	originalBaseURL := utils.GetEOLAPIBaseURL()
	defer utils.SetEOLAPIBaseURL(originalBaseURL)

	testURL := "https://example.com/api/v1/products"
	utils.SetEOLAPIBaseURL(testURL)

	got := utils.GetEOLAPIBaseURL()
	if got != testURL {
		t.Errorf("EOL API URL not properly configured: got %s, want %s", got, testURL)
	}
}

// Test Options with different platform architectures.
func TestOptions_DifferentArchitectures(t *testing.T) {
	architectures := []string{"amd64", "arm64", "386", "arm"}

	for _, arch := range architectures {
		t.Run(arch, func(t *testing.T) {
			opts := &Options{
				ImageName: "test:latest",
				TargetPlatform: &types.PatchPlatform{
					Platform: v1.Platform{
						OS:           "linux",
						Architecture: arch,
					},
				},
			}

			assert.Equal(t, arch, opts.TargetPlatform.Architecture)
			assert.Equal(t, "linux", opts.TargetPlatform.OS)
		})
	}
}

// Test Options validation scenarios.
func TestOptions_ValidationScenarios(t *testing.T) {
	testCases := []struct {
		name     string
		opts     *Options
		expected string
	}{
		{
			name: "Valid options with all fields",
			opts: &Options{
				ImageName:     "nginx:latest",
				WorkingFolder: "/tmp/patch",
				IgnoreError:   false,
				TargetPlatform: &types.PatchPlatform{
					Platform: v1.Platform{OS: "linux", Architecture: "amd64"},
				},
			},
			expected: "nginx:latest",
		},
		{
			name: "Empty image name",
			opts: &Options{
				ImageName:     "",
				WorkingFolder: "/tmp/patch",
			},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.opts.ImageName)
		})
	}
}

func TestAddResultAnnotations(t *testing.T) {
	lineageDigest := digest.FromString("selected-base")
	result := gwclient.NewResult()
	annotations := map[string]string{
		pkgmgr.ChiselReleaseAnnotation: "ubuntu-24.04",
		pkgmgr.ChiselVersionAnnotation: "v1.4.2",
		v1.AnnotationBaseImageName:     "docker.io/library/alpine:3.20",
		v1.AnnotationBaseImageDigest:   lineageDigest.String(),
	}

	addResultAnnotations(result, annotations)

	assert.Equal(t, []byte("ubuntu-24.04"), result.Metadata[exptypes.AnnotationManifestKey(nil, pkgmgr.ChiselReleaseAnnotation)])
	assert.Equal(t, []byte("v1.4.2"), result.Metadata[exptypes.AnnotationManifestKey(nil, pkgmgr.ChiselVersionAnnotation)])
	assert.Equal(t, []byte("docker.io/library/alpine:3.20"), result.Metadata[exptypes.AnnotationManifestKey(nil, v1.AnnotationBaseImageName)])
	assert.Equal(t, []byte(lineageDigest.String()), result.Metadata[exptypes.AnnotationManifestKey(nil, v1.AnnotationBaseImageDigest)])
}

func TestSourceLineageForPatch(t *testing.T) {
	dgst := digest.FromString("selected-base")
	tests := []struct {
		name   string
		config *buildkit.Config
		opts   *Options
		want   *types.SourceLineage
	}{
		{
			name: "first multi-platform patch uses logical source name",
			config: &buildkit.Config{SourceLineage: &types.SourceLineage{
				Name:   "docker.io/library/alpine@" + dgst.String(),
				Digest: dgst,
			}},
			opts: &Options{SourceImageName: "alpine:3.20", ExpectedSourceDigest: dgst, RequireBaseManifest: true},
			want: &types.SourceLineage{Name: "docker.io/library/alpine:3.20", Digest: dgst},
		},
		{
			name: "unverified first multi-platform patch is omitted",
			config: &buildkit.Config{SourceLineage: &types.SourceLineage{
				Name:   "docker.io/library/alpine:3.20",
				Digest: dgst,
			}},
			opts: &Options{SourceImageName: "alpine:3.20", RequireBaseManifest: true},
		},
		{
			name: "validated re-patch retains recorded original name",
			config: &buildkit.Config{
				PatchedConfigData:      []byte(`{"config":{}}`),
				SourceLineageValidated: true,
				SourceLineage: &types.SourceLineage{
					Name:   "docker.io/library/alpine:3.20",
					Digest: dgst,
				},
			},
			opts: &Options{RequireBaseManifest: true},
			want: &types.SourceLineage{Name: "docker.io/library/alpine:3.20", Digest: dgst},
		},
		{
			name: "unverified old multi-platform re-patch is omitted",
			config: &buildkit.Config{
				PatchedConfigData: []byte(`{"config":{}}`),
				SourceLineage:     &types.SourceLineage{Name: "docker.io/library/alpine:3.20", Digest: dgst},
			},
			opts: &Options{RequireBaseManifest: true},
		},
		{
			name:   "incomplete lineage is omitted",
			config: &buildkit.Config{SourceLineage: &types.SourceLineage{Name: "docker.io/library/alpine:3.20"}},
			opts:   &Options{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sourceLineageForPatch(tt.config, tt.opts))
		})
	}
}

func TestSourceLineageAnnotationsAreAtomic(t *testing.T) {
	assert.Nil(t, sourceLineageAnnotations(nil))
	assert.Nil(t, sourceLineageAnnotations(&types.SourceLineage{Name: "docker.io/library/alpine:3.20"}))

	lineage := &types.SourceLineage{
		Name:   "docker.io/library/alpine:3.20",
		Digest: digest.FromString("selected-base"),
	}
	assert.Equal(t, map[string]string{
		v1.AnnotationBaseImageName:   lineage.Name,
		v1.AnnotationBaseImageDigest: lineage.Digest.String(),
	}, sourceLineageAnnotations(lineage))
}
