package pkgmgr

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/buildkit/client/llb"
	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestLocalChiselReleaseStateRejectsEscapingSymlink(t *testing.T) {
	releaseDir := t.TempDir()
	require.NoError(t, os.Symlink("../../outside", filepath.Join(releaseDir, "bad")))
	_, _, err := localChiselReleaseState(releaseDir)
	require.ErrorContains(t, err, "escapes the release directory")
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
