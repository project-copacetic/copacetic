// SPDX-License-Identifier: Apache-2.0

// copa-chisel-validate validates and reconciles Chisel-managed filesystem
// trees. It intentionally uses only the Go standard library so the tooling
// image can carry a small static binary.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type expectedManifest struct {
	Paths []expectedPath `json:"paths"`
}

type expectedPath struct {
	Path        string   `json:"path"`
	Mode        string   `json:"mode"`
	Slices      []string `json:"slices,omitempty"`
	SHA256      string   `json:"sha256,omitempty"`
	FinalSHA256 string   `json:"final_sha256,omitempty"`
	Size        uint64   `json:"size,omitempty"`
	Link        string   `json:"link,omitempty"`
	Inode       uint64   `json:"inode,omitempty"`
}

type fileIdentity struct {
	Device uint64
	Inode  uint64
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "reconcile" {
		if err := reconcileCommand(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "chisel filesystem reconciliation failed: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := validateCommand(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "chisel filesystem validation failed: %v\n", err)
		os.Exit(1)
	}
}

func validateCommand(args []string) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	root := flags.String("root", "", "filesystem root to validate")
	expected := flags.String("expected", "", "JSON file containing expected path records")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *root == "" || *expected == "" || flags.NArg() != 0 {
		return errors.New("usage: copa-chisel-validate --root ROOT --expected FILE")
	}
	manifest, err := readExpectedManifest(*expected)
	if err != nil {
		return err
	}
	return validate(*root, manifest)
}

func reconcileCommand(args []string) error {
	flags := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	targetPath := flags.String("target", "", "target root to update")
	stagedPath := flags.String("staged", "", "fresh Chisel root")
	oldExpected := flags.String("old", "", "old manifest path expectations")
	newExpected := flags.String("new", "", "new manifest path expectations")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *targetPath == "" || *stagedPath == "" || *oldExpected == "" || *newExpected == "" || flags.NArg() != 0 {
		return errors.New("usage: copa-chisel-validate reconcile --target ROOT --staged ROOT --old FILE --new FILE")
	}
	oldManifest, err := readExpectedManifest(*oldExpected)
	if err != nil {
		return fmt.Errorf("read old expectations: %w", err)
	}
	newManifest, err := readExpectedManifest(*newExpected)
	if err != nil {
		return fmt.Errorf("read new expectations: %w", err)
	}
	return reconcile(*targetPath, *stagedPath, oldManifest, newManifest)
}

func readExpectedManifest(file string) (expectedManifest, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return expectedManifest{}, fmt.Errorf("read expected manifest: %w", err)
	}
	var expected expectedManifest
	if err := json.Unmarshal(data, &expected); err != nil {
		return expectedManifest{}, fmt.Errorf("decode expected manifest: %w", err)
	}
	seen := make(map[string]struct{}, len(expected.Paths))
	for _, record := range expected.Paths {
		if _, exists := seen[record.Path]; exists {
			return expectedManifest{}, fmt.Errorf("duplicate expected path %q", record.Path)
		}
		seen[record.Path] = struct{}{}
		if _, err := rootedName(record.Path); err != nil {
			return expectedManifest{}, err
		}
	}
	return expected, nil
}

func validate(rootPath string, expected expectedManifest) error {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open root: %w", err)
	}
	defer root.Close()
	return validateRoot(root, expected)
}

func validateRoot(root *os.Root, expected expectedManifest) error {
	hardLinks := map[uint64][]fileIdentity{}
	for _, pathRecord := range expected.Paths {
		if err := validatePath(root, &pathRecord, hardLinks); err != nil {
			return err
		}
	}

	ids := make([]uint64, 0, len(hardLinks))
	for id := range hardLinks {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	seenActual := map[fileIdentity]uint64{}
	for _, id := range ids {
		actual := hardLinks[id]
		if len(actual) < 2 {
			return fmt.Errorf("hard-link group %d has fewer than two paths", id)
		}
		for _, identity := range actual[1:] {
			if identity != actual[0] {
				return fmt.Errorf("hard-link group %d does not share one device and inode", id)
			}
		}
		if other, ok := seenActual[actual[0]]; ok && other != id {
			return fmt.Errorf("manifest hard-link groups %d and %d unexpectedly share device/inode %+v", other, id, actual[0])
		}
		seenActual[actual[0]] = id
	}
	return nil
}

func validatePath(root *os.Root, record *expectedPath, hardLinks map[uint64][]fileIdentity) error {
	name, err := rootedName(record.Path)
	if err != nil {
		return err
	}
	if err := ensureNoSymlinkAncestors(root, name, false); err != nil {
		return fmt.Errorf("path %q: %w", record.Path, err)
	}

	info, err := root.Lstat(name)
	if err != nil {
		return fmt.Errorf("stat %q: %w", record.Path, err)
	}

	expectedMode, err := strconv.ParseUint(record.Mode, 8, 32)
	if err != nil {
		return fmt.Errorf("path %q has invalid mode %q: %w", record.Path, record.Mode, err)
	}
	actualMode := uint64(info.Mode().Perm())
	if info.Mode()&fs.ModeSticky != 0 {
		actualMode |= 0o1000
	}
	if actualMode != expectedMode&0o1777 {
		return fmt.Errorf("path %q mode is %04o, expected %04o", record.Path, actualMode, expectedMode&0o1777)
	}

	switch {
	case record.Link != "":
		if info.Mode()&fs.ModeSymlink == 0 {
			return fmt.Errorf("path %q is not a symlink", record.Path)
		}
		target, err := root.Readlink(name)
		if err != nil {
			return fmt.Errorf("read symlink %q: %w", record.Path, err)
		}
		if target != record.Link {
			return fmt.Errorf("path %q links to %q, expected %q", record.Path, target, record.Link)
		}
	case strings.HasSuffix(record.Path, "/"):
		if !info.IsDir() {
			return fmt.Errorf("path %q is not a directory", record.Path)
		}
	default:
		if !info.Mode().IsRegular() {
			return fmt.Errorf("path %q is not a regular file", record.Path)
		}
		if record.Size != 0 || record.SHA256 != "" || record.FinalSHA256 != "" {
			if info.Size() < 0 {
				return fmt.Errorf("path %q has negative size %d", record.Path, info.Size())
			}
			actualSize := uint64(info.Size()) // #nosec G115 -- non-negative value checked above.
			if actualSize != record.Size {
				return fmt.Errorf("path %q size is %d, expected %d", record.Path, actualSize, record.Size)
			}
		}
		digest := record.FinalSHA256
		if digest == "" {
			digest = record.SHA256
		}
		if digest != "" {
			actual, err := fileSHA256(root, name)
			if err != nil {
				return fmt.Errorf("hash %q: %w", record.Path, err)
			}
			if !strings.EqualFold(actual, digest) {
				return fmt.Errorf("path %q sha256 is %s, expected %s", record.Path, actual, digest)
			}
		}
	}

	if record.Inode != 0 {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("path %q does not expose inode metadata", record.Path)
		}
		if stat.Dev < 0 {
			return fmt.Errorf("path %q has invalid negative device number %d", record.Path, stat.Dev)
		}
		device := uint64(stat.Dev) // #nosec G115 -- non-negative value checked above.
		hardLinks[record.Inode] = append(hardLinks[record.Inode], fileIdentity{Device: device, Inode: stat.Ino})
	}
	return nil
}

func reconcile(targetPath, stagedPath string, oldManifest, newManifest expectedManifest) error {
	staged, err := os.OpenRoot(stagedPath)
	if err != nil {
		return fmt.Errorf("open staged root: %w", err)
	}
	defer staged.Close()
	if err := validateRoot(staged, newManifest); err != nil {
		return fmt.Errorf("staged root is invalid: %w", err)
	}
	if err := rejectUndeclaredStagedEntries(staged, newManifest); err != nil {
		return err
	}

	target, err := os.OpenRoot(targetPath)
	if err != nil {
		return fmt.Errorf("open target root: %w", err)
	}
	defer target.Close()

	oldByPath := pathMap(oldManifest)
	newByPath := pathMap(newManifest)
	if err := rejectNewPathCollisions(target, oldByPath, newByPath); err != nil {
		return err
	}
	if err := removeOldPaths(target, oldByPath, newByPath); err != nil {
		return err
	}
	if err := copyNewPaths(target, staged, oldByPath, newByPath); err != nil {
		return err
	}
	if err := validateRoot(target, newManifest); err != nil {
		return fmt.Errorf("reconciled target is invalid: %w", err)
	}
	return nil
}

func pathMap(manifest expectedManifest) map[string]expectedPath {
	result := make(map[string]expectedPath, len(manifest.Paths))
	for _, record := range manifest.Paths {
		result[record.Path] = record
	}
	return result
}

func rejectUndeclaredStagedEntries(staged *os.Root, manifest expectedManifest) error {
	declared := pathMap(manifest)
	return fs.WalkDir(staged.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." || entry.IsDir() {
			return nil
		}
		manifestPath := "/" + filepath.ToSlash(name)
		if _, ok := declared[manifestPath]; !ok {
			return fmt.Errorf("staged root contains undeclared non-directory path %q", manifestPath)
		}
		return nil
	})
}

func rejectNewPathCollisions(target *os.Root, oldByPath, newByPath map[string]expectedPath) error {
	paths := sortedPaths(newByPath, false)
	for _, manifestPath := range paths {
		if _, wasManaged := oldByPath[manifestPath]; wasManaged {
			continue
		}
		name, err := rootedName(manifestPath)
		if err != nil {
			return err
		}
		if err := ensureNoSymlinkAncestors(target, name, true); err != nil {
			return fmt.Errorf("new Chisel-managed path %q has unsafe target ancestry: %w", manifestPath, err)
		}
		if _, err := target.Lstat(name); err == nil {
			return fmt.Errorf("new Chisel-managed path %q would overwrite an existing path not owned by the original manifest", manifestPath)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("inspect new Chisel-managed path %q: %w", manifestPath, err)
		}
	}
	return nil
}

func removeOldPaths(target *os.Root, oldByPath, newByPath map[string]expectedPath) error {
	paths := sortedPaths(oldByPath, true)
	// Remove non-directories first, deepest paths first.
	for _, manifestPath := range paths {
		oldRecord := oldByPath[manifestPath]
		if isExpectedDir(&oldRecord) {
			continue
		}
		if err := removeManagedPath(target, manifestPath, false, true); err != nil {
			return err
		}
	}
	// Remove obsolete directories only when empty. A directory that changes
	// into a non-directory must be removed or reconciliation cannot proceed.
	for _, manifestPath := range paths {
		oldRecord := oldByPath[manifestPath]
		if !isExpectedDir(&oldRecord) || manifestPath == "/" {
			continue
		}
		newRecord, remains := newByPath[manifestPath]
		required := remains && !isExpectedDir(&newRecord)
		if remains && isExpectedDir(&newRecord) {
			continue
		}
		if err := removeManagedPath(target, manifestPath, true, required); err != nil {
			return err
		}
	}
	return nil
}

func removeManagedPath(root *os.Root, manifestPath string, directory, required bool) error {
	name, err := rootedName(manifestPath)
	if err != nil {
		return err
	}
	if err := ensureNoSymlinkAncestors(root, name, true); err != nil {
		return fmt.Errorf("refusing to remove managed path %q: %w", manifestPath, err)
	}
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect managed path %q: %w", manifestPath, err)
	}
	if directory && !info.IsDir() {
		// The exact path was managed by the old manifest, so removing a tampered
		// file/symlink at that location is safe.
		directory = false
	}
	if !directory && info.IsDir() && !required {
		return fmt.Errorf("managed non-directory path %q unexpectedly became a directory", manifestPath)
	}
	if err := root.Remove(name); err != nil {
		if directory && !required {
			// Obsolete managed directories are intentionally preserved when they
			// contain unmanaged application content.
			return nil
		}
		return fmt.Errorf("remove managed path %q: %w", manifestPath, err)
	}
	return nil
}

func copyNewPaths(target, staged *os.Root, oldByPath, newByPath map[string]expectedPath) error {
	paths := sortedPaths(newByPath, false)
	// Create explicit managed directories before files.
	for _, manifestPath := range paths {
		record := newByPath[manifestPath]
		if !isExpectedDir(&record) {
			continue
		}
		if err := ensurePathParents(target, staged, manifestPath); err != nil {
			return err
		}
		name, _ := rootedName(manifestPath)
		info, err := target.Lstat(name)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := target.Mkdir(name, expectedPermissions(&record)); err != nil {
				return fmt.Errorf("create managed directory %q: %w", manifestPath, err)
			}
		case err != nil:
			return fmt.Errorf("inspect managed directory %q: %w", manifestPath, err)
		case !info.IsDir():
			if _, wasManaged := oldByPath[manifestPath]; !wasManaged {
				return fmt.Errorf("managed directory %q collides with an unmanaged path", manifestPath)
			}
			if err := target.Remove(name); err != nil {
				return fmt.Errorf("replace managed directory %q: %w", manifestPath, err)
			}
			if err := target.Mkdir(name, expectedPermissions(&record)); err != nil {
				return fmt.Errorf("create managed directory %q: %w", manifestPath, err)
			}
		}
		if err := target.Chmod(name, expectedMode(&record)); err != nil {
			return fmt.Errorf("set mode on managed directory %q: %w", manifestPath, err)
		}
	}

	hardLinkGroups := map[uint64][]expectedPath{}
	for _, manifestPath := range paths {
		record := newByPath[manifestPath]
		if isExpectedDir(&record) {
			continue
		}
		if record.Inode != 0 {
			hardLinkGroups[record.Inode] = append(hardLinkGroups[record.Inode], record)
			continue
		}
		if err := copyPath(target, staged, &record); err != nil {
			return err
		}
	}

	ids := make([]uint64, 0, len(hardLinkGroups))
	for id := range hardLinkGroups {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		group := hardLinkGroups[id]
		sort.Slice(group, func(i, j int) bool { return group[i].Path < group[j].Path })
		if len(group) < 2 {
			return fmt.Errorf("hard-link group %d has fewer than two paths", id)
		}
		if err := copyPath(target, staged, &group[0]); err != nil {
			return err
		}
		firstName, _ := rootedName(group[0].Path)
		for _, record := range group[1:] {
			if err := ensurePathParents(target, staged, record.Path); err != nil {
				return err
			}
			name, _ := rootedName(record.Path)
			if err := target.Link(firstName, name); err != nil {
				return fmt.Errorf("create hard link %q to %q: %w", record.Path, group[0].Path, err)
			}
		}
	}
	return nil
}

func copyPath(target, staged *os.Root, record *expectedPath) error {
	if err := ensurePathParents(target, staged, record.Path); err != nil {
		return err
	}
	name, err := rootedName(record.Path)
	if err != nil {
		return err
	}
	if err := ensureNoSymlinkAncestors(staged, name, false); err != nil {
		return fmt.Errorf("staged path %q: %w", record.Path, err)
	}
	if record.Link != "" {
		link, err := staged.Readlink(name)
		if err != nil {
			return fmt.Errorf("read staged symlink %q: %w", record.Path, err)
		}
		if err := target.Symlink(link, name); err != nil {
			return fmt.Errorf("create managed symlink %q: %w", record.Path, err)
		}
		return nil
	}

	source, err := staged.Open(name)
	if err != nil {
		return fmt.Errorf("open staged file %q: %w", record.Path, err)
	}
	defer source.Close()
	destination, err := target.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, expectedPermissions(record))
	if err != nil {
		return fmt.Errorf("create managed file %q: %w", record.Path, err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if copyErr != nil {
		return fmt.Errorf("copy managed file %q: %w", record.Path, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close managed file %q: %w", record.Path, closeErr)
	}
	if err := target.Chmod(name, expectedMode(record)); err != nil {
		return fmt.Errorf("set mode on managed file %q: %w", record.Path, err)
	}
	return nil
}

func ensurePathParents(target, staged *os.Root, manifestPath string) error {
	name, err := rootedName(manifestPath)
	if err != nil {
		return err
	}
	parent := filepath.Dir(name)
	if parent == "." {
		return nil
	}
	parts := strings.Split(parent, string(filepath.Separator))
	current := ""
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := target.Lstat(current)
		if err == nil {
			if info.Mode()&fs.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("parent %q is not a real directory", "/"+filepath.ToSlash(current))
			}
			continue
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("inspect parent %q: %w", current, err)
		}
		stagedInfo, err := staged.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect staged parent %q: %w", current, err)
		}
		if stagedInfo.Mode()&fs.ModeSymlink != 0 || !stagedInfo.IsDir() {
			return fmt.Errorf("staged parent %q is not a real directory", "/"+filepath.ToSlash(current))
		}
		if err := target.Mkdir(current, stagedInfo.Mode().Perm()); err != nil {
			return fmt.Errorf("create parent %q: %w", current, err)
		}
	}
	return nil
}

func rootedName(manifestPath string) (string, error) {
	if manifestPath == "" || !strings.HasPrefix(manifestPath, "/") || strings.ContainsRune(manifestPath, '\x00') {
		return "", fmt.Errorf("unsafe expected path %q", manifestPath)
	}
	cleaned := filepath.Clean(filepath.FromSlash(manifestPath))
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("unsafe expected path %q", manifestPath)
	}
	name := strings.TrimPrefix(cleaned, string(filepath.Separator))
	if name == "" {
		return ".", nil
	}
	if name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("expected path escapes root: %q", manifestPath)
	}
	return name, nil
}

func ensureNoSymlinkAncestors(root *os.Root, name string, allowMissing bool) error {
	if name == "." {
		return nil
	}
	parent := filepath.Dir(name)
	if parent == "." {
		return nil
	}
	parts := strings.Split(parent, string(filepath.Separator))
	current := ""
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) && allowMissing {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect ancestor %q: %w", "/"+filepath.ToSlash(current), err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("ancestor %q is a symlink", "/"+filepath.ToSlash(current))
		}
		if !info.IsDir() {
			return fmt.Errorf("ancestor %q is not a directory", "/"+filepath.ToSlash(current))
		}
	}
	return nil
}

func sortedPaths(paths map[string]expectedPath, descending bool) []string {
	result := make([]string, 0, len(paths))
	for manifestPath := range paths {
		result = append(result, manifestPath)
	}
	sort.Slice(result, func(i, j int) bool {
		leftDepth := strings.Count(strings.Trim(result[i], "/"), "/")
		rightDepth := strings.Count(strings.Trim(result[j], "/"), "/")
		if leftDepth != rightDepth {
			if descending {
				return leftDepth > rightDepth
			}
			return leftDepth < rightDepth
		}
		if descending {
			return result[i] > result[j]
		}
		return result[i] < result[j]
	})
	return result
}

func isExpectedDir(record *expectedPath) bool {
	return strings.HasSuffix(record.Path, "/")
}

func expectedMode(record *expectedPath) fs.FileMode {
	mode, _ := strconv.ParseUint(record.Mode, 8, 32)
	result := fs.FileMode(mode & 0o777)
	if mode&0o1000 != 0 {
		result |= fs.ModeSticky
	}
	return result
}

func expectedPermissions(record *expectedPath) fs.FileMode {
	return expectedMode(record).Perm()
}

func fileSHA256(root *os.Root, name string) (string, error) {
	file, err := root.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
