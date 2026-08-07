// Package chiselverify validates a flattened image rootfs against the managed
// filesystem metadata in a native Chisel manifest.
package chiselverify

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"
)

type entryKind uint8

const (
	entryOther entryKind = iota
	entryDirectory
	entryRegular
	entrySymlink
)

type rootFSEntry struct {
	kind       entryKind
	mode       int64
	size       int64
	digest     string
	linkTarget string
	identity   uint64
}

type rootFSView struct {
	entries      map[string]rootFSEntry
	nextIdentity uint64
}

type pendingHardLink struct {
	name   string
	target string
}

type hardLinkMember struct {
	path     string
	identity uint64
}

// VerifyTar checks every path owned by manifest against a flattened rootfs tar
// stream. It validates path type, mode, regular-file size and digest, symbolic
// link target, and hard-link identity.
func VerifyTar(manifest *copachisel.Manifest, rootfs io.Reader) error {
	if manifest == nil {
		return fmt.Errorf("cannot validate managed rootfs: Chisel manifest is nil")
	}
	if rootfs == nil {
		return fmt.Errorf("cannot validate managed rootfs: rootfs tar reader is nil")
	}

	view, err := readRootFSTar(rootfs)
	if err != nil {
		return fmt.Errorf("cannot read flattened rootfs tar: %w", err)
	}
	if err := verifyManifest(manifest, view); err != nil {
		return fmt.Errorf("managed rootfs does not match Chisel manifest: %w", err)
	}
	return nil
}

func readRootFSTar(input io.Reader) (*rootFSView, error) {
	view := &rootFSView{entries: make(map[string]rootFSEntry)}
	reader := tar.NewReader(input)
	var pending []pendingHardLink

	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		name, err := normalizeRootFSPath(header.Name)
		if err != nil {
			return nil, err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if existing, ok := view.entries[name]; ok && existing.kind != entryDirectory {
				view.removePath(name)
			}
			view.entries[name] = rootFSEntry{kind: entryDirectory, mode: header.Mode}
		case tar.TypeReg, 0:
			view.removePath(name)
			hash := sha256.New()
			// #nosec G110 -- callers provide test-owned flattened image archives.
			written, err := io.Copy(hash, reader)
			if err != nil {
				return nil, fmt.Errorf("read regular file %q: %w", rootFSDisplayPath(name), err)
			}
			if written != header.Size {
				return nil, fmt.Errorf(
					"regular file %q yielded %d bytes, but its tar header declares %d bytes",
					rootFSDisplayPath(name), written, header.Size,
				)
			}
			view.entries[name] = rootFSEntry{
				kind:     entryRegular,
				mode:     header.Mode,
				size:     written,
				digest:   hex.EncodeToString(hash.Sum(nil)),
				identity: view.allocateIdentity(),
			}
		case tar.TypeSymlink:
			view.removePath(name)
			view.entries[name] = rootFSEntry{
				kind:       entrySymlink,
				mode:       header.Mode,
				linkTarget: header.Linkname,
				identity:   view.allocateIdentity(),
			}
		case tar.TypeLink:
			target, err := normalizeRootFSPath(header.Linkname)
			if err != nil {
				return nil, fmt.Errorf("hard link %q has invalid target: %w", rootFSDisplayPath(name), err)
			}
			view.removePath(name)
			if !view.copyHardLink(name, target) {
				pending = append(pending, pendingHardLink{name: name, target: target})
			}
		case tar.TypeXGlobalHeader, tar.TypeXHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			continue
		default:
			view.removePath(name)
			view.entries[name] = rootFSEntry{
				kind:     entryOther,
				mode:     header.Mode,
				identity: view.allocateIdentity(),
			}
		}
	}

	for len(pending) > 0 {
		unresolved := pending[:0]
		resolved := 0
		for _, link := range pending {
			if view.copyHardLink(link.name, link.target) {
				resolved++
				continue
			}
			unresolved = append(unresolved, link)
		}
		if resolved == 0 {
			return nil, fmt.Errorf(
				"hard link %q targets missing path %q",
				rootFSDisplayPath(unresolved[0].name),
				rootFSDisplayPath(unresolved[0].target),
			)
		}
		pending = unresolved
	}

	return view, nil
}

func verifyManifest(manifest *copachisel.Manifest, view *rootFSView) error {
	paths := make([]string, 0, len(manifest.OwnedPaths))
	for manifestPath := range manifest.OwnedPaths {
		paths = append(paths, manifestPath)
	}
	sort.Strings(paths)

	hardLinks := make(map[uint64][]hardLinkMember)
	for _, manifestPath := range paths {
		metadata := manifest.OwnedPaths[manifestPath]
		name, err := normalizeRootFSPath(manifestPath)
		if err != nil {
			return fmt.Errorf("manifest-owned path %q is invalid: %w", manifestPath, err)
		}
		entry, ok := view.entries[name]
		if !ok {
			return fmt.Errorf("manifest-owned path %q is missing from the rootfs", manifestPath)
		}

		expectedMode := int64(metadata.Mode) & 0o7777
		actualMode := entry.mode & 0o7777
		if actualMode != expectedMode {
			return fmt.Errorf(
				"manifest-owned path %q has mode %04o; expected %04o",
				manifestPath, actualMode, expectedMode,
			)
		}

		switch {
		case metadata.IsDir():
			if entry.kind != entryDirectory {
				return pathTypeError(manifestPath, "directory", entry.kind)
			}
		case metadata.IsSymlink():
			if entry.kind != entrySymlink {
				return pathTypeError(manifestPath, "symbolic link", entry.kind)
			}
			if entry.linkTarget != metadata.Link {
				return fmt.Errorf(
					"manifest-owned symbolic link %q targets %q; expected %q",
					manifestPath, entry.linkTarget, metadata.Link,
				)
			}
		case metadata.IsRegular():
			if entry.kind != entryRegular {
				return pathTypeError(manifestPath, "regular file", entry.kind)
			}
			expectedDigest := metadata.Digest()
			if metadata.Size != 0 || expectedDigest != "" {
				if entry.size < 0 {
					return fmt.Errorf("manifest-owned regular file %q has invalid negative size %d", manifestPath, entry.size)
				}
				if uint64(entry.size) != metadata.Size { // #nosec G115 -- negative sizes are rejected above.
					return fmt.Errorf(
						"manifest-owned regular file %q has size %d; expected %d",
						manifestPath, entry.size, metadata.Size,
					)
				}
			}
			if expectedDigest != "" {
				digestField := "sha256"
				if metadata.FinalSHA256 != "" {
					digestField = "final_sha256"
				}
				if !strings.EqualFold(entry.digest, expectedDigest) {
					return fmt.Errorf(
						"manifest-owned regular file %q has sha256 %s; expected %s from %s",
						manifestPath, entry.digest, expectedDigest, digestField,
					)
				}
			}
		default:
			return fmt.Errorf("manifest-owned path %q has no recognized Chisel path type", manifestPath)
		}

		if metadata.Inode != 0 {
			if entry.identity == 0 {
				return fmt.Errorf("manifest hard-link path %q has no rootfs identity", manifestPath)
			}
			hardLinks[metadata.Inode] = append(hardLinks[metadata.Inode], hardLinkMember{
				path:     manifestPath,
				identity: entry.identity,
			})
		}
	}

	actualIdentityOwners := make(map[uint64]uint64)
	inodes := make([]uint64, 0, len(hardLinks))
	for inode := range hardLinks {
		inodes = append(inodes, inode)
	}
	sort.Slice(inodes, func(i, j int) bool { return inodes[i] < inodes[j] })
	for _, inode := range inodes {
		members := hardLinks[inode]
		if len(members) < 2 {
			return fmt.Errorf(
				"manifest hard-link group %d contains only path %q; expected at least two paths",
				inode, members[0].path,
			)
		}
		expectedIdentity := members[0].identity
		for _, member := range members[1:] {
			if member.identity != expectedIdentity {
				return fmt.Errorf(
					"manifest hard-link group %d is broken: path %q has rootfs identity %d, but path %q has identity %d",
					inode, member.path, member.identity, members[0].path, expectedIdentity,
				)
			}
		}
		if previousInode, exists := actualIdentityOwners[expectedIdentity]; exists && previousInode != inode {
			return fmt.Errorf(
				"manifest hard-link groups %d and %d unexpectedly share rootfs identity %d",
				previousInode, inode, expectedIdentity,
			)
		}
		actualIdentityOwners[expectedIdentity] = inode
	}

	return nil
}

func pathTypeError(manifestPath, expected string, actual entryKind) error {
	return fmt.Errorf(
		"manifest-owned path %q is a %s in the rootfs; expected %s",
		manifestPath, actual.String(), expected,
	)
}

func (kind entryKind) String() string {
	switch kind {
	case entryDirectory:
		return "directory"
	case entryRegular:
		return "regular file"
	case entrySymlink:
		return "symbolic link"
	default:
		return "special file"
	}
}

func (view *rootFSView) allocateIdentity() uint64 {
	view.nextIdentity++
	return view.nextIdentity
}

func (view *rootFSView) copyHardLink(name, target string) bool {
	entry, ok := view.entries[target]
	if !ok {
		return false
	}
	view.entries[name] = entry
	return true
}

func (view *rootFSView) removePath(name string) {
	delete(view.entries, name)
	prefix := name + "/"
	for candidate := range view.entries {
		if strings.HasPrefix(candidate, prefix) {
			delete(view.entries, candidate)
		}
	}
}

func normalizeRootFSPath(value string) (string, error) {
	original := value
	value = strings.TrimPrefix(strings.ReplaceAll(value, "\\", "/"), "./")
	value = strings.TrimLeft(value, "/")
	cleaned := path.Clean(value)
	if cleaned == "" {
		cleaned = "."
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("path %q escapes the rootfs", original)
	}
	return cleaned, nil
}

func rootFSDisplayPath(name string) string {
	if name == "." {
		return "/"
	}
	return "/" + name
}
