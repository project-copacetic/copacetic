package pkgmgr

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	fstypes "github.com/tonistiigi/fsutil/types"

	"github.com/project-copacetic/copacetic/mocks"
	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestChiselStateExtractionLimits(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		limit   int64
		extract func(context.Context, gwclient.Client, *llb.State) ([]byte, error)
	}{
		{
			name:    "native manifest",
			path:    chiselManifestPath,
			limit:   maxChiselManifestInputBytes,
			extract: extractNativeChiselManifest,
		},
		{
			name:    "os release",
			path:    "/etc/os-release",
			limit:   maxChiselOSReleaseBytes,
			extract: extractChiselOSRelease,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ref := &mocks.MockReference{}
			ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: test.path}).
				Return(&fstypes.Stat{Size: test.limit + 1}, nil).
				Once()
			result := gwclient.NewResult()
			result.SetRef(ref)
			client := &mocks.MockGWClient{}
			client.On("Solve", mock.Anything, mock.Anything).
				Return(result, nil).
				Once()
			state := llb.Scratch()

			_, err := test.extract(t.Context(), client, &state)
			require.ErrorContains(t, err, fmt.Sprintf("maximum allowed size of %d bytes", test.limit))
			ref.AssertNotCalled(t, "ReadFile", mock.Anything, mock.Anything)
			client.AssertExpectations(t)
			ref.AssertExpectations(t)
		})
	}
}

func TestValidateChiselUpgrade(t *testing.T) {
	base := &copachisel.Manifest{
		Packages: map[string]copachisel.Package{
			"base-files": {Name: "base-files", Version: "1.0-1", SHA256: digestA, Architecture: "amd64"},
		},
		Slices: []string{"base-files_base"},
	}

	tests := []struct {
		name    string
		updated *copachisel.Manifest
		err     string
	}{
		{
			name: "upgrade with transitive dependency",
			updated: &copachisel.Manifest{
				Packages: map[string]copachisel.Package{
					"base-files": {Name: "base-files", Version: "1.0-2", SHA256: digestB, Architecture: "amd64"},
					"libc6":      {Name: "libc6", Version: "2.39-1", SHA256: digestC, Architecture: "amd64"},
				},
				Slices: []string{"base-files_base", "libc6_libs"},
			},
		},
		{
			name: "downgrade",
			updated: &copachisel.Manifest{
				Packages: map[string]copachisel.Package{
					"base-files": {Name: "base-files", Version: "0.9-1", SHA256: digestB, Architecture: "amd64"},
				},
				Slices: []string{"base-files_base"},
			},
			err: "downgraded",
		},
		{
			name: "missing original slice",
			updated: &copachisel.Manifest{
				Packages: map[string]copachisel.Package{
					"base-files": {Name: "base-files", Version: "1.0-2", SHA256: digestB, Architecture: "amd64"},
				},
			},
			err: "dropped originally selected slice",
		},
		{
			name: "wrong architecture",
			updated: &copachisel.Manifest{
				Packages: map[string]copachisel.Package{
					"base-files": {Name: "base-files", Version: "1.0-2", SHA256: digestB, Architecture: "arm64"},
				},
				Slices: []string{"base-files_base"},
			},
			err: "does not match target",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateChiselUpgrade(base, test.updated, "amd64")
			if test.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, test.err)
			}
		})
	}
}

func TestChiselManifestsEqual(t *testing.T) {
	manifest := &copachisel.Manifest{
		Packages: map[string]copachisel.Package{
			"base-files": {Name: "base-files", Version: "1.0-1", SHA256: digestA, Architecture: "amd64"},
		},
		Slices: []string{"base-files_base"},
		OwnedPaths: map[string]copachisel.PathMetadata{
			"/etc/": {Path: "/etc/", Mode: 0o755, Slices: []string{"base-files_base"}},
		},
	}
	copyManifest := &copachisel.Manifest{
		Packages: map[string]copachisel.Package{
			"base-files": manifest.Packages["base-files"],
		},
		Slices: []string{"base-files_base"},
		OwnedPaths: map[string]copachisel.PathMetadata{
			"/etc/": manifest.OwnedPaths["/etc/"],
		},
	}
	assert.True(t, chiselManifestsEqual(manifest, copyManifest))
	copyManifest.Packages["base-files"] = copachisel.Package{Name: "base-files", Version: "1.0-2", SHA256: digestB, Architecture: "amd64"}
	assert.False(t, chiselManifestsEqual(manifest, copyManifest))
}

func TestMarshalChiselExpectedManifest(t *testing.T) {
	manifest := &copachisel.Manifest{OwnedPaths: map[string]copachisel.PathMetadata{
		"/z":  {Path: "/z", Mode: fs.FileMode(0o600), Slices: []string{"pkg_data"}, SHA256: digestA, Size: 3},
		"/a/": {Path: "/a/", Mode: fs.FileMode(0o755), Slices: []string{"pkg_data"}},
	}}
	data, err := marshalChiselExpectedManifest(manifest)
	require.NoError(t, err)
	var expected chiselExpectedManifest
	require.NoError(t, json.Unmarshal(data, &expected))
	require.Len(t, expected.Paths, 2)
	assert.Equal(t, "/a/", expected.Paths[0].Path)
	assert.Equal(t, "0755", expected.Paths[0].Mode)
	assert.Equal(t, "/z", expected.Paths[1].Path)
}

func TestLocalChiselReleaseState(t *testing.T) {
	releaseDir := t.TempDir()
	writePackageManagerTestFile(t, filepath.Join(releaseDir, "chisel.yaml"), []byte("format: v1\n"), 0o644)
	require.NoError(t, os.Mkdir(filepath.Join(releaseDir, "slices"), 0o755))
	writePackageManagerTestFile(t, filepath.Join(releaseDir, "slices", "base.yaml"), []byte("package: base-files\n"), 0o644)

	_, firstDigest, err := localChiselReleaseState(releaseDir)
	require.NoError(t, err)
	_, secondDigest, err := localChiselReleaseState(releaseDir)
	require.NoError(t, err)
	assert.Len(t, firstDigest, 64)
	assert.Equal(t, firstDigest, secondDigest)
}

func TestLocalChiselReleaseStateLengthFramesRegularFilePayloads(t *testing.T) {
	firstReleaseDir := t.TempDir()
	secondReleaseDir := t.TempDir()
	prefix := []byte("prefix")
	suffix := []byte("suffix")
	fileMode := os.FileMode(0o644)
	secondFileHeader := fmt.Appendf(nil, "/b\x00%o\x00", fileMode)

	writePackageManagerTestFile(t, filepath.Join(firstReleaseDir, "a"),
		append(append(append([]byte{}, prefix...), secondFileHeader...), suffix...), fileMode)
	writePackageManagerTestFile(t, filepath.Join(secondReleaseDir, "a"), prefix, fileMode)
	writePackageManagerTestFile(t, filepath.Join(secondReleaseDir, "b"), suffix, fileMode)

	_, firstDigest, err := localChiselReleaseState(firstReleaseDir)
	require.NoError(t, err)
	_, secondDigest, err := localChiselReleaseState(secondReleaseDir)
	require.NoError(t, err)
	assert.NotEqual(t, firstDigest, secondDigest)
}

func TestLocalChiselReleaseStateLengthFramesSymlinkTargets(t *testing.T) {
	releaseDir := t.TempDir()
	const target = "."
	symlinkPath := filepath.Join(releaseDir, "link")
	require.NoError(t, os.Symlink(target, symlinkPath))

	_, digest, err := localChiselReleaseState(releaseDir)
	require.NoError(t, err)

	info, err := os.Lstat(symlinkPath)
	require.NoError(t, err)
	expected := sha256.New()
	fmt.Fprintf(expected, "/link\x00%o\x00", info.Mode())
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(target)))
	expected.Write(length[:])
	expected.Write([]byte(target))
	assert.Equal(t, fmt.Sprintf("%x", expected.Sum(nil)), digest)
}

func TestLocalChiselReleaseStateRejectsEscapingSymlink(t *testing.T) {
	releaseDir := t.TempDir()
	require.NoError(t, os.Symlink("../../outside", filepath.Join(releaseDir, "bad")))
	_, _, err := localChiselReleaseState(releaseDir)
	require.ErrorContains(t, err, "escapes the release directory")
}

func TestLocalChiselReleaseStateRejectsEscapeThroughInTreeSymlink(t *testing.T) {
	parent := t.TempDir()
	releaseDir := filepath.Join(parent, "release")
	require.NoError(t, os.Mkdir(releaseDir, 0o755))
	writePackageManagerTestFile(t, filepath.Join(parent, "outside"), []byte("outside"), 0o644)
	require.NoError(t, os.Symlink(".", filepath.Join(releaseDir, "pivot")))
	require.NoError(t, os.Symlink("pivot/../outside", filepath.Join(releaseDir, "bad")))

	_, _, err := localChiselReleaseState(releaseDir)
	require.ErrorContains(t, err, "does not resolve safely within the release directory")
}

func TestMaterializeChiselRelease(t *testing.T) {
	state, argument, provenance, err := materializeChiselRelease(t.Context(), nil, llb.Scratch(), copachisel.Release{
		Kind:     copachisel.ReleaseNamed,
		Location: "ubuntu-24.04",
	})
	require.NoError(t, err)
	assert.Equal(t, "ubuntu-24.04", argument)
	assert.Equal(t, "ubuntu-24.04", provenance)
	_, err = state.Marshal(t.Context())
	require.NoError(t, err)
}

func TestReconcileChiselStateCompressesLargeExpectations(t *testing.T) {
	const pathCount = 24000
	oldMarker := "OLD_CHISEL_EXPECTATION_SENTINEL"
	newMarker := "NEW_CHISEL_EXPECTATION_SENTINEL"
	oldManifest := largeChiselExpectationManifest(oldMarker, pathCount)
	newManifest := largeChiselExpectationManifest(newMarker, pathCount)

	oldExpected, err := marshalChiselExpectedManifest(oldManifest)
	require.NoError(t, err)
	newExpected, err := marshalChiselExpectedManifest(newManifest)
	require.NoError(t, err)
	assert.Greater(t, len(oldExpected), 8<<20)
	assert.Greater(t, len(newExpected), 8<<20)

	ref := new(mocks.MockReference)
	ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{Filename: chiselValidationMark}).
		Return([]byte{}, nil).
		Once()
	result := gwclient.NewResult()
	result.SetRef(ref)
	client := new(mocks.MockGWClient)
	var captured gwclient.SolveRequest
	client.On("Solve", mock.Anything, mock.MatchedBy(func(request gwclient.SolveRequest) bool {
		captured = request
		return true
	})).Return(result, nil).Once()

	_, err = reconcileChiselState(
		t.Context(),
		client,
		llb.Scratch(),
		llb.Scratch(),
		llb.Scratch(),
		oldManifest,
		newManifest,
	)
	require.NoError(t, err)

	definition, err := captured.Definition.MarshalVT()
	require.NoError(t, err)
	assert.Less(t, len(definition), 16<<20)
	assert.NotContains(t, string(definition), oldMarker)
	assert.NotContains(t, string(definition), newMarker)
	assert.Contains(t, string(definition), "zstd -q -d -c")
	assert.True(t, bytes.Contains(definition, []byte{0x28, 0xb5, 0x2f, 0xfd}), "definition should contain zstd-compressed expectations")
	client.AssertExpectations(t)
	ref.AssertExpectations(t)
}

func TestCompressChiselExpectationsRejectsOversizedInlinePayload(t *testing.T) {
	payload := make([]byte, maxChiselExpectationInlineBytes+1)
	_, err := rand.Read(payload)
	require.NoError(t, err)

	_, err = compressChiselExpectations(payload)
	require.ErrorContains(t, err, "BuildKit inline transfer limit")
}

func largeChiselExpectationManifest(marker string, pathCount int) *copachisel.Manifest {
	ownedPaths := make(map[string]copachisel.PathMetadata, pathCount)
	for index := range pathCount {
		manifestPath := fmt.Sprintf(
			"/usr/share/copa/%s/%05d-%s",
			marker,
			index,
			strings.Repeat("x", 180),
		)
		ownedPaths[manifestPath] = copachisel.PathMetadata{
			Path:   manifestPath,
			Mode:   0o644,
			Slices: []string{"base-files_data"},
			SHA256: digestA,
			Size:   1,
		}
	}
	return &copachisel.Manifest{OwnedPaths: ownedPaths}
}

func TestNativeTargetedPatchError(t *testing.T) {
	assert.Equal(t,
		"targeted patching of native Chisel manifests is not supported; omit --report to run a comprehensive Chisel update",
		nativeTargetedPatchError,
	)
}

const (
	digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func writePackageManagerTestFile(t *testing.T, path string, contents []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, contents, 0o600))
	require.NoError(t, os.Chmod(path, mode))
}
