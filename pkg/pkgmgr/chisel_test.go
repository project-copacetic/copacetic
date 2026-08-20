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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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

func TestValidateChiselUpgradeRejectsOriginalWrongArchitecture(t *testing.T) {
	original := &copachisel.Manifest{
		Packages: map[string]copachisel.Package{
			"base-files": {Name: "base-files", Version: "1.0-1", SHA256: digestA, Architecture: "arm64"},
		},
		Slices: []string{"base-files_base"},
	}
	updated := &copachisel.Manifest{
		Packages: map[string]copachisel.Package{
			"base-files": {Name: "base-files", Version: "1.0-2", SHA256: digestB, Architecture: "amd64"},
		},
		Slices: []string{"base-files_base"},
	}

	err := validateChiselUpgrade(original, updated, "amd64")
	require.ErrorContains(t, err, `original Chisel package "base-files" architecture "arm64" does not match target "amd64"`)
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

	firstState, firstDigest, err := localChiselReleaseState(releaseDir)
	require.NoError(t, err)
	secondState, secondDigest, err := localChiselReleaseState(releaseDir)
	require.NoError(t, err)
	assert.Len(t, firstDigest, 64)
	assert.Equal(t, firstDigest, secondDigest)
	firstDefinition, err := firstState.Marshal(t.Context())
	require.NoError(t, err)
	secondDefinition, err := secondState.Marshal(t.Context())
	require.NoError(t, err)
	assert.Equal(t, firstDefinition.Def, secondDefinition.Def)
}

func TestMaterializeLocalChiselReleaseCompressesLargeRelease(t *testing.T) {
	releaseDir := t.TempDir()
	const marker = "LARGE_LOCAL_CHISEL_RELEASE_SENTINEL"
	contents := bytes.Repeat([]byte(marker), (20<<20)/len(marker)+1)
	writePackageManagerTestFile(t, filepath.Join(releaseDir, "large.yaml"), contents, 0o644)
	_, expectedDigest, err := localChiselReleaseState(releaseDir)
	require.NoError(t, err)

	state, argument, provenance, err := materializeChiselRelease(t.Context(), nil, llb.Scratch(), copachisel.Release{
		Kind:     copachisel.ReleaseLocal,
		Location: releaseDir,
	})
	require.NoError(t, err)
	assert.Equal(t, chiselReleaseRoot, argument)
	assert.Equal(t, fmt.Sprintf("local:%s@sha256:%s", filepath.Base(releaseDir), expectedDigest), provenance)
	definition, err := state.Marshal(t.Context())
	require.NoError(t, err)
	serialized, err := definition.ToPB().MarshalVT()
	require.NoError(t, err)

	assert.Less(t, len(serialized), 16<<20)
	assert.NotContains(t, string(serialized), marker)
	assert.Contains(t, string(serialized), "zstd -q -d -c")
	assert.Contains(t, string(serialized), "tar -xpf -")
	assert.True(t, bytes.Contains(serialized, []byte{0x28, 0xb5, 0x2f, 0xfd}), "definition should contain a zstd-compressed release archive")
}

func TestLocalChiselReleaseStateRejectsCompressedArchiveOverInlineLimit(t *testing.T) {
	releaseDir := t.TempDir()
	contents := deterministicChiselTestBytes(maxLocalReleaseInlineBytes + (1 << 20))
	writePackageManagerTestFile(t, filepath.Join(releaseDir, "incompressible.yaml"), contents, 0o644)

	_, _, err := localChiselReleaseState(releaseDir)
	require.ErrorContains(t, err, fmt.Sprintf("exceeding the %d MiB BuildKit inline transfer limit", maxLocalReleaseInlineBytes>>20))
}

func TestLocalChiselReleaseStateRejectsReleaseOverContentLimit(t *testing.T) {
	releaseDir := t.TempDir()
	path := filepath.Join(releaseDir, "oversized.yaml")
	writePackageManagerTestFile(t, path, nil, 0o644)
	require.NoError(t, os.Truncate(path, maxLocalReleaseBytes+1))

	_, _, err := localChiselReleaseState(releaseDir)
	require.ErrorContains(t, err, fmt.Sprintf("exceeds the %d MiB size limit", maxLocalReleaseBytes>>20))
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

func TestLocalChiselReleaseStateRejectsUnsafeSymlinks(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(*testing.T, string)
		errContains string
	}{
		{
			name: "absolute target",
			setup: func(t *testing.T, root string) {
				require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(root, "bad")))
			},
			errContains: "has an absolute target",
		},
		{
			name: "dangling target",
			setup: func(t *testing.T, root string) {
				require.NoError(t, os.Symlink("missing", filepath.Join(root, "bad")))
			},
			errContains: "does not resolve safely",
		},
		{
			name: "cyclic target",
			setup: func(t *testing.T, root string) {
				require.NoError(t, os.Symlink("two", filepath.Join(root, "one")))
				require.NoError(t, os.Symlink("one", filepath.Join(root, "two")))
			},
			errContains: "does not resolve safely",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			releaseDir := t.TempDir()
			test.setup(t, releaseDir)
			_, _, err := localChiselReleaseState(releaseDir)
			require.ErrorContains(t, err, test.errContains)
		})
	}
}

func TestLocalChiselReleaseStateRejectsSpecialFiles(t *testing.T) {
	releaseDir := t.TempDir()
	socketPath := filepath.Join(releaseDir, "unsupported-socket")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("Unix sockets are unavailable: %v", err)
	}
	t.Cleanup(func() { require.NoError(t, listener.Close()) })

	_, _, err = localChiselReleaseState(releaseDir)
	require.ErrorContains(t, err, `unsupported file type at "unsupported-socket"`)
}

func TestLocalChiselReleaseStateEntryLimitBoundary(t *testing.T) {
	releaseDir := t.TempDir()
	for index := range maxLocalReleaseFiles {
		require.NoError(t, os.Mkdir(filepath.Join(releaseDir, fmt.Sprintf("entry-%05d", index)), 0o755))
	}
	_, _, err := localChiselReleaseState(releaseDir)
	require.NoError(t, err)

	require.NoError(t, os.Mkdir(filepath.Join(releaseDir, "one-too-many"), 0o755))
	_, _, err = localChiselReleaseState(releaseDir)
	require.ErrorContains(t, err, fmt.Sprintf("more than %d entries", maxLocalReleaseFiles))
}

func TestLocalChiselReleaseStateContentLimitBoundary(t *testing.T) {
	releaseDir := t.TempDir()
	path := filepath.Join(releaseDir, "exact-limit.yaml")
	writePackageManagerTestFile(t, path, nil, 0o644)
	require.NoError(t, os.Truncate(path, maxLocalReleaseBytes))

	_, _, err := localChiselReleaseState(releaseDir)
	require.NoError(t, err)
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

func TestGitChiselReleaseCloneScriptResolvesPinnedRevisions(t *testing.T) {
	requireGitTestTools(t)
	repository, commit := createGitReleaseRepository(t, map[string]string{"slices/base.yaml": "release-data"}, nil)
	runGitTestCommand(t, repository, "tag", "lightweight")
	runGitTestCommand(t, repository, "tag", "-a", "annotated", "-m", "annotated release")

	tests := []struct {
		name     string
		revision string
	}{
		{name: "full commit", revision: commit},
		{name: "unique short commit", revision: commit[:12]},
		{name: "lightweight tag", revision: "lightweight"},
		{name: "annotated tag", revision: "annotated"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			releaseDir, revision := executeGitReleaseCloneScript(t, repository, test.revision, 100, 1<<20)
			assert.Equal(t, commit, revision)
			assert.FileExists(t, filepath.Join(releaseDir, "slices", "base.yaml"))
			assert.NoDirExists(t, filepath.Join(releaseDir, ".git"))
			assert.NoFileExists(t, filepath.Join(filepath.Dir(releaseDir), "home", ".gitconfig"))
		})
	}
}

func TestGitChiselReleaseCloneScriptRejectsUnresolvedRevision(t *testing.T) {
	requireGitTestTools(t)
	repository, _ := createGitReleaseRepository(t, map[string]string{"release.yaml": "data"}, nil)
	output, err := executeGitReleaseCloneScriptError(t, repository, "deadbee", 100, 1<<20)
	require.Error(t, err)
	assert.Contains(t, output, "does not uniquely resolve to an advertised commit")

	output, err = executeGitReleaseCloneScriptError(t, repository, strings.Repeat("f", 40), 100, 1<<20)
	require.Error(t, err)
	assert.Contains(t, output, "fatal:")
}

func TestGitChiselReleaseCloneScriptBoundsMaterializedTree(t *testing.T) {
	requireGitTestTools(t)
	repository, commit := createGitReleaseRepository(t, map[string]string{
		"one.yaml": "12345",
		"two.yaml": "x",
	}, nil)

	_, resolved := executeGitReleaseCloneScript(t, repository, commit, 2, 6)
	assert.Equal(t, commit, resolved)

	output, err := executeGitReleaseCloneScriptError(t, repository, commit, 1, 1<<20)
	require.Error(t, err)
	assert.Contains(t, output, "contains more than 1 entries")

	output, err = executeGitReleaseCloneScriptError(t, repository, commit, 100, 4)
	require.Error(t, err)
	assert.Contains(t, output, "exceeds the configured content size limit")
}

func TestGitChiselReleaseCloneScriptCountsNewlinePaths(t *testing.T) {
	requireGitTestTools(t)
	root := t.TempDir()
	writePackageManagerTestFile(t, filepath.Join(root, "large"), []byte("x"), 0o600)
	repository, commit := createGitReleaseRepository(t, map[string]string{
		"small":        "x",
		"small\nlarge": strings.Repeat("x", 1024),
	}, nil)
	releaseDir := filepath.Join(root, "release")
	revisionFile := filepath.Join(root, "home", "revision")

	output, err := runGitReleaseCloneScript(root, releaseDir, revisionFile, repository, commit, 100, 16)
	require.Error(t, err)
	assert.Contains(t, string(output), "exceeds the configured content size limit")
}

func TestGitChiselReleaseCloneScriptRejectsSymlinkIntoRemovedGitDirectory(t *testing.T) {
	requireGitTestTools(t)
	repository, commit := createGitReleaseRepository(t,
		map[string]string{"release.yaml": "data"},
		map[string]string{"git-config": ".git/config"},
	)

	output, err := executeGitReleaseCloneScriptError(t, repository, commit, 100, 1<<20)
	require.Error(t, err)
	assert.Contains(t, output, "does not resolve safely")
}

func TestGitChiselReleaseCloneScriptDoesNotOverwriteRevisionCollision(t *testing.T) {
	requireGitTestTools(t)
	repository, commit := createGitReleaseRepository(t,
		map[string]string{"chisel.yaml": "original release contents"},
		map[string]string{".copa-revision": "chisel.yaml"},
	)

	releaseDir, revision := executeGitReleaseCloneScript(t, repository, commit, 100, 1<<20)
	assert.Equal(t, commit, revision)
	contents, err := os.ReadFile(filepath.Join(releaseDir, "chisel.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "original release contents", string(contents))
	collision := filepath.Join(releaseDir, ".copa-revision")
	info, err := os.Lstat(collision)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink)
	target, err := os.Readlink(collision)
	require.NoError(t, err)
	assert.Equal(t, "chisel.yaml", target)
}

func TestGitChiselRevisionFileIsOutsideReleaseDirectory(t *testing.T) {
	assert.NotEqual(t, chiselReleaseRoot, chiselGitRevisionFile)
	assert.False(t, strings.HasPrefix(chiselGitRevisionFile, chiselReleaseRoot+"/"))
}

func TestGitChiselReleaseCloneScriptIgnoresGitConfiguration(t *testing.T) {
	requireGitTestTools(t)
	repository, commit := createGitReleaseRepository(t, map[string]string{"release.yaml": "data"}, nil)
	root := t.TempDir()
	home := filepath.Join(root, "home")
	require.NoError(t, os.MkdirAll(home, 0o700))
	globalConfig := filepath.Join(home, ".gitconfig")
	systemConfig := filepath.Join(root, "system.gitconfig")
	for _, config := range []string{globalConfig, systemConfig} {
		runGitConfigTestCommand(t, config, "protocol.file.allow", "never")
		runGitConfigTestCommand(t, config, "credential.helper", "!false")
	}

	releaseDir := filepath.Join(root, "release")
	revisionFile := filepath.Join(home, "revision")
	output, err := runGitReleaseCloneScriptWithEnv(
		root,
		releaseDir,
		revisionFile,
		repository,
		commit,
		100,
		1<<20,
		"GIT_CONFIG_SYSTEM="+systemConfig,
	)
	require.NoError(t, err, "clone script output:\n%s", output)
	assert.FileExists(t, filepath.Join(releaseDir, "release.yaml"))
	revisionData, err := os.ReadFile(revisionFile)
	require.NoError(t, err)
	assert.Equal(t, commit, strings.TrimSpace(string(revisionData)))
}

func TestGitChiselReleaseCloneScriptDoesNotInvokeConfiguredCredentialHelpers(t *testing.T) {
	requireGitTestTools(t)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("WWW-Authenticate", `Basic realm="copa-test"`)
		response.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	root := t.TempDir()
	home := filepath.Join(root, "home")
	require.NoError(t, os.MkdirAll(home, 0o700))
	marker := filepath.Join(root, "credential-helper-invoked")
	helper := filepath.Join(root, "credential-helper.sh")
	require.NoError(t, os.WriteFile(helper, fmt.Appendf(nil, "#!/bin/sh\nprintf invoked > %q\n", marker), 0o600))
	require.NoError(t, os.Chmod(helper, 0o700))
	globalConfig := filepath.Join(home, ".gitconfig")
	systemConfig := filepath.Join(root, "system.gitconfig")
	for _, config := range []string{globalConfig, systemConfig} {
		runGitConfigTestCommand(t, config, "credential.helper", "!"+helper)
	}

	releaseDir := filepath.Join(root, "release")
	revisionFile := filepath.Join(home, "revision")
	_, err := runGitReleaseCloneScriptWithEnv(
		root,
		releaseDir,
		revisionFile,
		server.URL+"/release.git",
		"deadbee",
		100,
		1<<20,
		"GIT_CONFIG_SYSTEM="+systemConfig,
	)
	require.Error(t, err)
	assert.NoFileExists(t, marker)
}

func TestGitChiselReleaseCloneScriptRejectsUnsafeSymlinks(t *testing.T) {
	requireGitTestTools(t)
	tests := []struct {
		name        string
		target      string
		errContains string
	}{
		{name: "absolute", target: "/etc/passwd", errContains: "has an absolute target"},
		{name: "dangling", target: "missing", errContains: "does not resolve safely"},
		{name: "escaping", target: "../outside", errContains: "escapes the release directory"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository, commit := createGitReleaseRepository(t, map[string]string{"release.yaml": "data"}, map[string]string{"bad": test.target})
			output, err := executeGitReleaseCloneScriptError(t, repository, commit, 100, 1<<20)
			require.Error(t, err)
			assert.Contains(t, output, test.errContains)
		})
	}
	t.Run("cyclic", func(t *testing.T) {
		repository, commit := createGitReleaseRepository(t, map[string]string{"release.yaml": "data"}, map[string]string{"one": "two", "two": "one"})
		output, err := executeGitReleaseCloneScriptError(t, repository, commit, 100, 1<<20)
		require.Error(t, err)
		assert.Contains(t, output, "does not resolve safely")
	})
}

func requireGitTestTools(t *testing.T) {
	t.Helper()
	for _, name := range []string{"awk", "find", "git", "grep", "readlink", "sed", "sh", "sort", "tr", "wc", "xargs"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is required for Git release materialization tests", name)
		}
	}
}

func createGitReleaseRepository(t *testing.T, files, symlinks map[string]string) (string, string) {
	t.Helper()
	repository := t.TempDir()
	runGitTestCommand(t, repository, "init", "-q")
	runGitTestCommand(t, repository, "config", "user.name", "Copa Test")
	runGitTestCommand(t, repository, "config", "user.email", "copa@example.invalid")
	for name, contents := range files {
		path := filepath.Join(repository, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	}
	for name, target := range symlinks {
		path := filepath.Join(repository, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.Symlink(target, path))
	}
	runGitTestCommand(t, repository, "add", ".")
	runGitTestCommand(t, repository, "commit", "-q", "-m", "release")
	return repository, strings.TrimSpace(runGitTestCommand(t, repository, "rev-parse", "HEAD"))
}

func executeGitReleaseCloneScript(t *testing.T, repository, revision string, maxFiles, maxBytes int) (string, string) {
	t.Helper()
	root := t.TempDir()
	releaseDir := filepath.Join(root, "release")
	revisionFile := filepath.Join(root, "home", "revision")
	output, err := runGitReleaseCloneScript(root, releaseDir, revisionFile, repository, revision, maxFiles, maxBytes)
	require.NoError(t, err, "clone script output:\n%s", output)
	revisionData, err := os.ReadFile(revisionFile)
	require.NoError(t, err)
	return releaseDir, strings.TrimSpace(string(revisionData))
}

func executeGitReleaseCloneScriptError(t *testing.T, repository, revision string, maxFiles, maxBytes int) (string, error) {
	t.Helper()
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "outside"), []byte("outside"), 0o600))
	releaseDir := filepath.Join(root, "release")
	revisionFile := filepath.Join(root, "home", "revision")
	output, err := runGitReleaseCloneScript(root, releaseDir, revisionFile, repository, revision, maxFiles, maxBytes)
	return string(output), err
}

func runGitReleaseCloneScript(root, releaseDir, revisionFile, repository, revision string, maxFiles, maxBytes int) ([]byte, error) {
	return runGitReleaseCloneScriptWithEnv(root, releaseDir, revisionFile, repository, revision, maxFiles, maxBytes)
}

func runGitReleaseCloneScriptWithEnv(
	root, releaseDir, revisionFile, repository, revision string,
	maxFiles, maxBytes int,
	extraEnv ...string,
) ([]byte, error) {
	command := exec.Command("sh", "-c", gitChiselReleaseCloneScript)
	command.Dir = root
	command.Env = append(os.Environ(),
		"RELEASE_DIR="+releaseDir,
		"REVISION_FILE="+revisionFile,
		"RELEASE_URL="+repository,
		"RELEASE_REV="+revision,
		fmt.Sprintf("MAX_RELEASE_FILES=%d", maxFiles),
		fmt.Sprintf("MAX_RELEASE_BYTES=%d", maxBytes),
		"HOME="+filepath.Join(root, "home"),
	)
	command.Env = append(command.Env, extraEnv...)
	return command.CombinedOutput()
}

func runGitConfigTestCommand(t *testing.T, configFile string, args ...string) {
	t.Helper()
	commandArgs := append([]string{"config", "--file", configFile}, args...)
	command := exec.Command("git", commandArgs...)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "git config %v failed:\n%s", args, output)
}

func runGitTestCommand(t *testing.T, repository string, args ...string) string {
	t.Helper()
	commandArgs := append([]string{"-C", repository}, args...)
	command := exec.Command("git", commandArgs...)
	output, err := command.CombinedOutput()
	require.NoError(t, err, "git %v failed:\n%s", args, output)
	return string(output)
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

func deterministicChiselTestBytes(size int) []byte {
	contents := make([]byte, 0, size)
	var counter [8]byte
	for index := uint64(0); len(contents) < size; index++ {
		binary.BigEndian.PutUint64(counter[:], index)
		digest := sha256.Sum256(counter[:])
		contents = append(contents, digest[:]...)
	}
	return contents[:size]
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
