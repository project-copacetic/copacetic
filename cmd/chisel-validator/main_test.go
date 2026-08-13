// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	baseFilesSlice            = "base_files"
	linksDirectory            = "/links/"
	managedDirectory          = "/managed/"
	managedObsoleteDirectory  = "/managed/obsolete/"
	obsoletePathComponentName = "obsolete"
)

func TestValidate(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "usr"), 0o755))
	content := []byte("hello chisel\n")
	file := filepath.Join(root, "usr", "data")
	writeFileWithMode(t, file, content, 0o644)
	require.NoError(t, os.Link(file, filepath.Join(root, "usr", "data-link")))
	require.NoError(t, os.Symlink("data", filepath.Join(root, "usr", "current")))
	symlinkInfo, err := os.Lstat(filepath.Join(root, "usr", "current"))
	require.NoError(t, err)

	digest := sha256.Sum256(content)
	expected := expectedManifest{Paths: []expectedPath{
		{Path: "/usr/", Mode: "0755", Slices: []string{baseFilesSlice}},
		{Path: "/usr/current", Mode: fmt.Sprintf("0%o", symlinkInfo.Mode().Perm()), Slices: []string{baseFilesSlice}, Link: "data"},
		{Path: "/usr/data", Mode: "0644", Slices: []string{baseFilesSlice}, FinalSHA256: hex.EncodeToString(digest[:]), Size: uint64(len(content)), Inode: 1},
		{Path: "/usr/data-link", Mode: "0644", Slices: []string{baseFilesSlice}, SHA256: hex.EncodeToString(digest[:]), Size: uint64(len(content)), Inode: 1},
	}}
	expectedFile := filepath.Join(t.TempDir(), "expected.json")
	data, err := json.Marshal(expected)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(expectedFile, data, 0o600))

	manifest, err := readExpectedManifest(expectedFile)
	require.NoError(t, err)
	require.NoError(t, validate(root, manifest))
}

func TestValidateRejectsMissingSpecialModeBits(t *testing.T) {
	testCases := []struct {
		name         string
		manifestPath string
		mode         string
		directory    bool
	}{
		{name: "setuid", manifestPath: "/entry", mode: "04755"},
		{name: "setgid", manifestPath: "/entry/", mode: "02755", directory: true},
		{name: "sticky", manifestPath: "/entry/", mode: "01755", directory: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "entry")
			if testCase.directory {
				require.NoError(t, os.Mkdir(path, 0o755))
			} else {
				writeFileWithMode(t, path, nil, 0o755)
			}

			err := validate(root, expectedManifest{Paths: []expectedPath{{
				Path: testCase.manifestPath,
				Mode: testCase.mode,
			}}})
			require.ErrorContains(t, err, "mode is 0755")
		})
	}
}

func TestReconcilePreservesSpecialModeBits(t *testing.T) {
	target := t.TempDir()
	staged := t.TempDir()

	require.NoError(t, os.Mkdir(filepath.Join(staged, "bin"), 0o755))
	toolPath := filepath.Join(staged, "bin", "tool")
	writeFileWithMode(t, toolPath, nil, 0o755|fs.ModeSetuid|fs.ModeSetgid)
	require.NoError(t, os.Mkdir(filepath.Join(staged, "shared"), 0o770))
	require.NoError(t, os.Chmod(filepath.Join(staged, "shared"), 0o770|fs.ModeSetgid|fs.ModeSticky))

	manifest := expectedManifest{Paths: []expectedPath{
		{Path: "/bin/", Mode: "0755"},
		{Path: "/bin/tool", Mode: "06755"},
		{Path: "/shared/", Mode: "03770"},
	}}
	require.NoError(t, reconcile(target, staged, expectedManifest{}, manifest))

	toolInfo, err := os.Lstat(filepath.Join(target, "bin", "tool"))
	require.NoError(t, err)
	assert.Equal(t, uint64(0o6755), unixMode(toolInfo.Mode()))
	sharedInfo, err := os.Lstat(filepath.Join(target, "shared"))
	require.NoError(t, err)
	assert.Equal(t, uint64(0o3770), unixMode(sharedInfo.Mode()))
	require.NoError(t, validate(target, manifest))
}

func TestIdentityFromFileInfo(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	linked := filepath.Join(root, "linked")
	other := filepath.Join(root, "other")
	require.NoError(t, os.WriteFile(original, nil, 0o600))
	require.NoError(t, os.Link(original, linked))
	require.NoError(t, os.WriteFile(other, nil, 0o600))

	identityFor := func(path string) fileIdentity {
		t.Helper()
		info, err := os.Lstat(path)
		require.NoError(t, err)
		identity, err := identityFromFileInfo(path, info)
		require.NoError(t, err)
		return identity
	}

	originalIdentity := identityFor(original)
	assert.Equal(t, originalIdentity, identityFor(linked))
	assert.NotEqual(t, originalIdentity, identityFor(other))
}

func TestNonNegativeDevice(t *testing.T) {
	device, ok := nonNegativeDevice(int64(42))
	require.True(t, ok)
	assert.Equal(t, uint64(42), device)

	device, ok = nonNegativeDevice(uint64(1 << 63))
	require.True(t, ok)
	assert.Equal(t, uint64(1<<63), device)

	_, ok = nonNegativeDevice(int64(-1))
	assert.False(t, ok)
}

func TestValidateRejectsDigestMismatch(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "file"), []byte("unexpected"), 0o600))
	expected := expectedManifest{Paths: []expectedPath{{
		Path:   "/file",
		Mode:   "0600",
		SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Size:   uint64(len("unexpected")),
	}}}
	expectedFile := filepath.Join(t.TempDir(), "expected.json")
	data, err := json.Marshal(expected)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(expectedFile, data, 0o600))

	manifest, err := readExpectedManifest(expectedFile)
	require.NoError(t, err)
	require.ErrorContains(t, validate(root, manifest), "sha256")
}

func TestValidateRejectsSplitHardLinkGroup(t *testing.T) {
	root := t.TempDir()
	writeFileWithMode(t, filepath.Join(root, "one"), []byte("same"), 0o644)
	writeFileWithMode(t, filepath.Join(root, "two"), []byte("same"), 0o644)
	digest := sha256.Sum256([]byte("same"))
	expected := expectedManifest{Paths: []expectedPath{
		{Path: "/one", Mode: "0644", SHA256: hex.EncodeToString(digest[:]), Size: 4, Inode: 1},
		{Path: "/two", Mode: "0644", SHA256: hex.EncodeToString(digest[:]), Size: 4, Inode: 1},
	}}
	expectedFile := filepath.Join(t.TempDir(), "expected.json")
	data, err := json.Marshal(expected)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(expectedFile, data, 0o600))

	manifest, err := readExpectedManifest(expectedFile)
	require.NoError(t, err)
	require.ErrorContains(t, validate(root, manifest), "does not share one device and inode")
}

func TestReconcilePreservesUnmanagedContentAndHardLinks(t *testing.T) {
	target := t.TempDir()
	staged := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(target, "managed", obsoletePathComponentName), 0o755))
	writeFileWithMode(t, filepath.Join(target, "managed", "file"), []byte("old"), 0o644)
	require.NoError(t, os.WriteFile(filepath.Join(target, "managed", obsoletePathComponentName, "old"), []byte("remove"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(target, "sentinel"), []byte("preserve"), 0o600))

	require.NoError(t, os.MkdirAll(filepath.Join(staged, "managed"), 0o755))
	content := []byte("new managed content")
	writeFileWithMode(t, filepath.Join(staged, "managed", "file"), content, 0o640)
	require.NoError(t, os.Link(filepath.Join(staged, "managed", "file"), filepath.Join(staged, "managed", "file-link")))
	digest := sha256.Sum256(content)

	oldManifest := expectedManifest{Paths: []expectedPath{
		{Path: managedDirectory, Mode: "0755"},
		{Path: "/managed/file", Mode: "0644", SHA256: hashString("old"), Size: 3},
		{Path: managedObsoleteDirectory, Mode: "0755"},
		{Path: "/managed/obsolete/old", Mode: "0600", SHA256: hashString("remove"), Size: 6},
	}}
	newManifest := expectedManifest{Paths: []expectedPath{
		{Path: managedDirectory, Mode: "0755"},
		{Path: "/managed/file", Mode: "0640", SHA256: hex.EncodeToString(digest[:]), Size: uint64(len(content)), Inode: 1},
		{Path: "/managed/file-link", Mode: "0640", SHA256: hex.EncodeToString(digest[:]), Size: uint64(len(content)), Inode: 1},
	}}

	require.NoError(t, reconcile(target, staged, oldManifest, newManifest))
	got, err := os.ReadFile(filepath.Join(target, "managed", "file"))
	require.NoError(t, err)
	assert.Equal(t, content, got)
	got, err = os.ReadFile(filepath.Join(target, "sentinel"))
	require.NoError(t, err)
	assert.Equal(t, []byte("preserve"), got)
	_, err = os.Stat(filepath.Join(target, "managed", obsoletePathComponentName))
	assert.ErrorIs(t, err, os.ErrNotExist)
	one, err := os.Stat(filepath.Join(target, "managed", "file"))
	require.NoError(t, err)
	two, err := os.Stat(filepath.Join(target, "managed", "file-link"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(one, two))
}

func TestReconcilePreservesUnmanagedContentInObsoleteManagedDirectory(t *testing.T) {
	target := t.TempDir()
	staged := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(target, "managed", obsoletePathComponentName), 0o755))
	sentinel := filepath.Join(target, "managed", obsoletePathComponentName, "application-data")
	writeFileWithMode(t, sentinel, []byte("preserve"), 0o600)
	require.NoError(t, os.Mkdir(filepath.Join(staged, "managed"), 0o755))

	oldManifest := expectedManifest{Paths: []expectedPath{
		{Path: managedDirectory, Mode: "0755"},
		{Path: managedObsoleteDirectory, Mode: "0755"},
	}}
	newManifest := expectedManifest{Paths: []expectedPath{{Path: managedDirectory, Mode: "0755"}}}

	require.NoError(t, reconcile(target, staged, oldManifest, newManifest))
	got, err := os.ReadFile(sentinel)
	require.NoError(t, err)
	assert.Equal(t, []byte("preserve"), got)
	assert.DirExists(t, filepath.Join(target, "managed", obsoletePathComponentName))
	require.NoError(t, validate(target, newManifest))
}

func TestReconcileRemovesNestedManagedBranchAndPreservesUnmanagedBranch(t *testing.T) {
	target := t.TempDir()
	staged := t.TempDir()
	managedBranch := filepath.Join(target, "managed", obsoletePathComponentName, "remove", "deep")
	unmanagedBranch := filepath.Join(target, "managed", obsoletePathComponentName, "keep")
	require.NoError(t, os.MkdirAll(managedBranch, 0o755))
	require.NoError(t, os.MkdirAll(unmanagedBranch, 0o755))
	managedFile := filepath.Join(managedBranch, "payload")
	writeFileWithMode(t, managedFile, []byte("remove"), 0o600)
	unmanagedFile := filepath.Join(unmanagedBranch, "application-data")
	writeFileWithMode(t, unmanagedFile, []byte("preserve"), 0o600)
	require.NoError(t, os.Mkdir(filepath.Join(staged, "managed"), 0o755))

	oldManifest := expectedManifest{Paths: []expectedPath{
		{Path: managedDirectory, Mode: "0755"},
		{Path: managedObsoleteDirectory, Mode: "0755"},
		{Path: "/managed/obsolete/remove/", Mode: "0755"},
		{Path: "/managed/obsolete/remove/deep/", Mode: "0755"},
		{Path: "/managed/obsolete/remove/deep/payload", Mode: "0600", SHA256: hashString("remove"), Size: 6},
		{Path: "/managed/obsolete/keep/", Mode: "0755"},
	}}
	newManifest := expectedManifest{Paths: []expectedPath{{Path: managedDirectory, Mode: "0755"}}}

	require.NoError(t, reconcile(target, staged, oldManifest, newManifest))
	_, err := os.Lstat(filepath.Join(target, "managed", obsoletePathComponentName, "remove"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	got, err := os.ReadFile(unmanagedFile)
	require.NoError(t, err)
	assert.Equal(t, []byte("preserve"), got)
	assert.DirExists(t, filepath.Join(target, "managed", obsoletePathComponentName, "keep"))
	assert.DirExists(t, filepath.Join(target, "managed", obsoletePathComponentName))
	require.NoError(t, validate(target, newManifest))
}

func TestIsDirectoryNotEmptyError(t *testing.T) {
	assert.True(t, isDirectoryNotEmptyError(&os.PathError{Op: "remove", Path: obsoletePathComponentName, Err: syscall.ENOTEMPTY}))
	assert.True(t, isDirectoryNotEmptyError(&os.PathError{Op: "remove", Path: obsoletePathComponentName, Err: syscall.EEXIST}))
	assert.False(t, isDirectoryNotEmptyError(&os.PathError{Op: "remove", Path: obsoletePathComponentName, Err: syscall.EPERM}))
}

func TestRemoveManagedPathReturnsUnexpectedDirectoryRemovalError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based removal failure requires an unprivileged user")
	}

	target := t.TempDir()
	locked := filepath.Join(target, "locked")
	obsolete := filepath.Join(locked, obsoletePathComponentName)
	require.NoError(t, os.MkdirAll(obsolete, 0o755))
	root, err := os.OpenRoot(target)
	require.NoError(t, err)
	defer root.Close()

	require.NoError(t, os.Chmod(locked, 0o555))
	t.Cleanup(func() {
		require.NoError(t, os.Chmod(locked, 0o755))
	})

	err = removeManagedPath(root, "/locked/obsolete/", true, false)
	require.ErrorContains(t, err, "remove managed path")
	assert.ErrorIs(t, err, os.ErrPermission)
	assert.DirExists(t, obsolete)
}

func TestReconcileHardLinkedSymlinks(t *testing.T) {
	target := t.TempDir()
	staged := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(staged, "links"), 0o755))
	first := filepath.Join(staged, "links", "first")
	require.NoError(t, os.Symlink("../target", first))
	linkWithinRoot(t, staged, "links/first", "links/second")
	linkMode := symlinkMode(t, first)

	manifest := expectedManifest{Paths: []expectedPath{
		{Path: linksDirectory, Mode: "0755"},
		{Path: "/links/first", Mode: linkMode, Link: "../target", Inode: 7},
		{Path: "/links/second", Mode: linkMode, Link: "../target", Inode: 7},
	}}

	require.NoError(t, reconcile(target, staged, expectedManifest{}, manifest))
	require.NoError(t, validate(target, manifest))
	firstTarget, err := os.Readlink(filepath.Join(target, "links", "first"))
	require.NoError(t, err)
	assert.Equal(t, "../target", firstTarget)
	secondTarget, err := os.Readlink(filepath.Join(target, "links", "second"))
	require.NoError(t, err)
	assert.Equal(t, "../target", secondTarget)
	firstInfo, err := os.Lstat(filepath.Join(target, "links", "first"))
	require.NoError(t, err)
	secondInfo, err := os.Lstat(filepath.Join(target, "links", "second"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(firstInfo, secondInfo))
}

func TestReconcileRejectsInvalidHardLinkedSymlinksBeforeMutation(t *testing.T) {
	testCases := []struct {
		name      string
		stage     func(*testing.T, string) expectedManifest
		errorText string
	}{
		{
			name: "mixed regular file and symlink",
			stage: func(t *testing.T, staged string) expectedManifest {
				t.Helper()
				require.NoError(t, os.Mkdir(filepath.Join(staged, "links"), 0o755))
				file := filepath.Join(staged, "links", "file")
				writeFileWithMode(t, file, []byte("content"), 0o644)
				link := filepath.Join(staged, "links", "link")
				require.NoError(t, os.Symlink("target", link))
				return expectedManifest{Paths: []expectedPath{
					{Path: linksDirectory, Mode: "0755"},
					{Path: "/links/file", Mode: "0644", SHA256: hashString("content"), Size: 7, Inode: 9},
					{Path: "/links/link", Mode: symlinkMode(t, link), Link: "target", Inode: 9},
				}}
			},
			errorText: "does not share one device and inode",
		},
		{
			name: "changed symlink target",
			stage: func(t *testing.T, staged string) expectedManifest {
				t.Helper()
				require.NoError(t, os.Mkdir(filepath.Join(staged, "links"), 0o755))
				first := filepath.Join(staged, "links", "first")
				require.NoError(t, os.Symlink("actual-target", first))
				linkWithinRoot(t, staged, "links/first", "links/second")
				linkMode := symlinkMode(t, first)
				return expectedManifest{Paths: []expectedPath{
					{Path: linksDirectory, Mode: "0755"},
					{Path: "/links/first", Mode: linkMode, Link: "actual-target", Inode: 10},
					{Path: "/links/second", Mode: linkMode, Link: "different-target", Inode: 10},
				}}
			},
			errorText: "links to \"actual-target\", expected \"different-target\"",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			target := t.TempDir()
			staged := t.TempDir()
			sentinel := filepath.Join(target, "application-data")
			writeFileWithMode(t, sentinel, []byte("preserve"), 0o600)
			manifest := testCase.stage(t, staged)

			err := reconcile(target, staged, expectedManifest{}, manifest)
			require.ErrorContains(t, err, "staged root is invalid")
			require.ErrorContains(t, err, testCase.errorText)
			got, readErr := os.ReadFile(sentinel)
			require.NoError(t, readErr)
			assert.Equal(t, []byte("preserve"), got)
			_, statErr := os.Lstat(filepath.Join(target, "links"))
			assert.ErrorIs(t, statErr, os.ErrNotExist)
		})
	}
}

func TestReconcileManagedPathTypeTransitions(t *testing.T) {
	t.Run("directory to file", func(t *testing.T) {
		target := t.TempDir()
		staged := t.TempDir()
		require.NoError(t, os.Mkdir(filepath.Join(target, "managed"), 0o755))
		content := []byte("replacement")
		writeFileWithMode(t, filepath.Join(staged, "managed"), content, 0o640)

		oldManifest := expectedManifest{Paths: []expectedPath{{Path: managedDirectory, Mode: "0755"}}}
		newManifest := expectedManifest{Paths: []expectedPath{{
			Path:   "/managed",
			Mode:   "0640",
			SHA256: hashString(string(content)),
			Size:   uint64(len(content)),
		}}}

		require.NoError(t, reconcile(target, staged, oldManifest, newManifest))
		info, err := os.Lstat(filepath.Join(target, "managed"))
		require.NoError(t, err)
		assert.True(t, info.Mode().IsRegular())
		got, err := os.ReadFile(filepath.Join(target, "managed"))
		require.NoError(t, err)
		assert.Equal(t, content, got)
	})

	t.Run("file to directory", func(t *testing.T) {
		target := t.TempDir()
		staged := t.TempDir()
		writeFileWithMode(t, filepath.Join(target, "managed"), []byte("old"), 0o640)
		require.NoError(t, os.Mkdir(filepath.Join(staged, "managed"), 0o750))

		oldManifest := expectedManifest{Paths: []expectedPath{{
			Path:   "/managed",
			Mode:   "0640",
			SHA256: hashString("old"),
			Size:   3,
		}}}
		newManifest := expectedManifest{Paths: []expectedPath{{Path: managedDirectory, Mode: "0750"}}}

		require.NoError(t, reconcile(target, staged, oldManifest, newManifest))
		info, err := os.Lstat(filepath.Join(target, "managed"))
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("file to directory with child", func(t *testing.T) {
		target := t.TempDir()
		staged := t.TempDir()
		writeFileWithMode(t, filepath.Join(target, "a"), []byte("old"), 0o640)
		require.NoError(t, os.Mkdir(filepath.Join(staged, "a"), 0o750))
		content := []byte("new child")
		writeFileWithMode(t, filepath.Join(staged, "a", "b"), content, 0o600)

		oldManifest := expectedManifest{Paths: []expectedPath{{
			Path:   "/a",
			Mode:   "0640",
			SHA256: hashString("old"),
			Size:   3,
		}}}
		newManifest := expectedManifest{Paths: []expectedPath{
			{Path: "/a/", Mode: "0750"},
			{Path: "/a/b", Mode: "0600", SHA256: hashString(string(content)), Size: uint64(len(content))},
		}}

		require.NoError(t, reconcile(target, staged, oldManifest, newManifest))
		info, err := os.Lstat(filepath.Join(target, "a"))
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		got, err := os.ReadFile(filepath.Join(target, "a", "b"))
		require.NoError(t, err)
		assert.Equal(t, content, got)
	})
}

func TestReconcileRejectsSymlinkAncestorWithoutDeletingTarget(t *testing.T) {
	target := t.TempDir()
	staged := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(target, "unmanaged"), 0o755))
	victim := filepath.Join(target, "unmanaged", "victim")
	require.NoError(t, os.WriteFile(victim, []byte("keep"), 0o600))
	require.NoError(t, os.Symlink("unmanaged", filepath.Join(target, "managed-parent")))

	oldManifest := expectedManifest{Paths: []expectedPath{{
		Path: "/managed-parent/victim", Mode: "0600", SHA256: hashString("keep"), Size: 4,
	}}}
	err := reconcile(target, staged, oldManifest, expectedManifest{})
	require.ErrorContains(t, err, "ancestor \"/managed-parent\" is a symlink")
	got, readErr := os.ReadFile(victim)
	require.NoError(t, readErr)
	assert.Equal(t, []byte("keep"), got)
}

func TestReconcileRejectsUndeclaredStagedFile(t *testing.T) {
	target := t.TempDir()
	staged := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(staged, "undeclared"), []byte("bad"), 0o600))
	err := reconcile(target, staged, expectedManifest{}, expectedManifest{})
	require.ErrorContains(t, err, "undeclared non-directory path")
}

func TestReconcileRejectsUnmanagedCollision(t *testing.T) {
	t.Run("exact path", func(t *testing.T) {
		target := t.TempDir()
		staged := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(target, "collision"), []byte("application"), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(staged, "collision"), []byte("chisel"), 0o600))
		manifest := expectedManifest{Paths: []expectedPath{{
			Path: "/collision", Mode: "0600", SHA256: hashString("chisel"), Size: 6,
		}}}
		err := reconcile(target, staged, expectedManifest{}, manifest)
		require.ErrorContains(t, err, "would overwrite an existing path not owned")
		got, readErr := os.ReadFile(filepath.Join(target, "collision"))
		require.NoError(t, readErr)
		assert.Equal(t, []byte("application"), got)
	})

	t.Run("non-directory ancestor", func(t *testing.T) {
		target := t.TempDir()
		staged := t.TempDir()
		content := []byte("application")
		writeFileWithMode(t, filepath.Join(target, "a"), content, 0o600)
		require.NoError(t, os.Mkdir(filepath.Join(staged, "a"), 0o755))
		writeFileWithMode(t, filepath.Join(staged, "a", "b"), []byte("chisel"), 0o600)
		manifest := expectedManifest{Paths: []expectedPath{{
			Path: "/a/b", Mode: "0600", SHA256: hashString("chisel"), Size: 6,
		}}}

		err := reconcile(target, staged, expectedManifest{}, manifest)
		require.ErrorContains(t, err, `ancestor "/a" is not a directory`)
		got, readErr := os.ReadFile(filepath.Join(target, "a"))
		require.NoError(t, readErr)
		assert.Equal(t, content, got)
	})
}

func hashString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func linkWithinRoot(t *testing.T, rootPath, oldName, newName string) {
	t.Helper()
	root, err := os.OpenRoot(rootPath)
	require.NoError(t, err)
	require.NoError(t, root.Link(oldName, newName))
	require.NoError(t, root.Close())
}

func symlinkMode(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Lstat(path)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&fs.ModeSymlink)
	return fmt.Sprintf("0%o", info.Mode().Perm())
}

func writeFileWithMode(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, 0o600))
	require.NoError(t, os.Chmod(path, mode))
}
