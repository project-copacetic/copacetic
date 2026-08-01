// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		{Path: "/usr/", Mode: "0755", Slices: []string{"base_files"}},
		{Path: "/usr/current", Mode: fmt.Sprintf("0%o", symlinkInfo.Mode().Perm()), Slices: []string{"base_files"}, Link: "data"},
		{Path: "/usr/data", Mode: "0644", Slices: []string{"base_files"}, FinalSHA256: hex.EncodeToString(digest[:]), Size: uint64(len(content)), Inode: 1},
		{Path: "/usr/data-link", Mode: "0644", Slices: []string{"base_files"}, SHA256: hex.EncodeToString(digest[:]), Size: uint64(len(content)), Inode: 1},
	}}
	expectedFile := filepath.Join(t.TempDir(), "expected.json")
	data, err := json.Marshal(expected)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(expectedFile, data, 0o600))

	manifest, err := readExpectedManifest(expectedFile)
	require.NoError(t, err)
	require.NoError(t, validate(root, manifest))
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
	require.NoError(t, os.MkdirAll(filepath.Join(target, "managed", "obsolete"), 0o755))
	writeFileWithMode(t, filepath.Join(target, "managed", "file"), []byte("old"), 0o644)
	require.NoError(t, os.WriteFile(filepath.Join(target, "managed", "obsolete", "old"), []byte("remove"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(target, "sentinel"), []byte("preserve"), 0o600))

	require.NoError(t, os.MkdirAll(filepath.Join(staged, "managed"), 0o755))
	content := []byte("new managed content")
	writeFileWithMode(t, filepath.Join(staged, "managed", "file"), content, 0o640)
	require.NoError(t, os.Link(filepath.Join(staged, "managed", "file"), filepath.Join(staged, "managed", "file-link")))
	digest := sha256.Sum256(content)

	oldManifest := expectedManifest{Paths: []expectedPath{
		{Path: "/managed/", Mode: "0755"},
		{Path: "/managed/file", Mode: "0644", SHA256: hashString("old"), Size: 3},
		{Path: "/managed/obsolete/", Mode: "0755"},
		{Path: "/managed/obsolete/old", Mode: "0600", SHA256: hashString("remove"), Size: 6},
	}}
	newManifest := expectedManifest{Paths: []expectedPath{
		{Path: "/managed/", Mode: "0755"},
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
	_, err = os.Stat(filepath.Join(target, "managed", "obsolete"))
	assert.ErrorIs(t, err, os.ErrNotExist)
	one, err := os.Stat(filepath.Join(target, "managed", "file"))
	require.NoError(t, err)
	two, err := os.Stat(filepath.Join(target, "managed", "file-link"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(one, two))
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
}

func hashString(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func writeFileWithMode(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, 0o600))
	require.NoError(t, os.Chmod(path, mode))
}
