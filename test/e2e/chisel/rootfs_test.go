package chisel

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"
	"github.com/stretchr/testify/require"
)

const manifestWallPath = "var/lib/chisel/manifest.wall"

type rootFSEntryKind uint8

const (
	rootFSEntryOther rootFSEntryKind = iota
	rootFSEntryDirectory
	rootFSEntryRegular
	rootFSEntrySymlink
)

type rootFSEntry struct {
	kind       rootFSEntryKind
	mode       int64
	size       int64
	digest     string
	linkTarget string
	identity   uint64
	data       []byte
}

type rootFSView struct {
	entries      map[string]rootFSEntry
	nextIdentity uint64
}

type pendingHardLink struct {
	name   string
	target string
}

type ociImageSnapshot struct {
	Config      imageConfig
	Manifest    *copachisel.Manifest
	RootFS      *rootFSView
	Annotations map[string]string
}

func newRootFSView() *rootFSView {
	return &rootFSView{entries: make(map[string]rootFSEntry)}
}

func rootFSViewFromTar(t *testing.T, tarPath string) *rootFSView {
	t.Helper()
	file, err := os.Open(tarPath)
	require.NoError(t, err)
	defer file.Close()

	view := newRootFSView()
	require.NoError(t, view.applyTar(file, false))
	return view
}

func captureOCIImage(t *testing.T, outputDir string, descriptor ociDescriptor) ociImageSnapshot {
	t.Helper()
	manifest := assertOCIManifestBlobsExist(t, outputDir, descriptor.Digest)

	configData := readOCIBlob(t, outputDir, manifest.Config.Digest)
	var config imageConfig
	require.NoError(t, json.Unmarshal(configData, &config))

	view := newRootFSView()
	for _, layer := range manifest.Layers {
		blobPath := ociBlobPath(t, outputDir, layer.Digest)
		reader, err := openLayer(blobPath)
		require.NoError(t, err, "open OCI layer %s", layer.Digest)
		err = view.applyTar(reader, true)
		closeErr := reader.Close()
		require.NoError(t, err, "apply OCI layer %s", layer.Digest)
		require.NoError(t, closeErr, "close OCI layer %s", layer.Digest)
	}

	manifestEntry, ok := view.entries[manifestWallPath]
	require.True(t, ok, "patched OCI rootfs is missing /%s", manifestWallPath)
	require.Equal(t, rootFSEntryRegular, manifestEntry.kind, "patched manifest.wall is not a regular file")
	require.NotEmpty(t, manifestEntry.data, "patched manifest.wall contents were not retained")
	parsed, err := copachisel.ParseManifest(bytes.NewReader(manifestEntry.data))
	require.NoError(t, err)

	return ociImageSnapshot{Config: config, Manifest: parsed, RootFS: view, Annotations: manifest.Annotations}
}

func ociBlobPath(t *testing.T, outputDir, digest string) string {
	t.Helper()
	parts := strings.SplitN(digest, ":", 2)
	require.Len(t, parts, 2)
	return filepath.Join(outputDir, "blobs", parts[0], parts[1])
}

type layerReadCloser struct {
	io.Reader
	close func() error
}

func (reader *layerReadCloser) Close() error {
	return reader.close()
}

func openLayer(blobPath string) (io.ReadCloser, error) {
	file, err := os.Open(blobPath)
	if err != nil {
		return nil, err
	}
	buffered := bufio.NewReader(file)
	magic, err := buffered.Peek(4)
	if err != nil && err != io.EOF {
		file.Close()
		return nil, err
	}

	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		compressed, err := gzip.NewReader(buffered)
		if err != nil {
			file.Close()
			return nil, err
		}
		return &layerReadCloser{
			Reader: compressed,
			close: func() error {
				compressedErr := compressed.Close()
				fileErr := file.Close()
				if compressedErr != nil {
					return compressedErr
				}
				return fileErr
			},
		}, nil
	case len(magic) == 4 && bytes.Equal(magic, []byte{0x28, 0xb5, 0x2f, 0xfd}):
		compressed, err := zstd.NewReader(buffered)
		if err != nil {
			file.Close()
			return nil, err
		}
		return &layerReadCloser{
			Reader: compressed,
			close: func() error {
				compressed.Close()
				return file.Close()
			},
		}, nil
	default:
		return &layerReadCloser{Reader: buffered, close: file.Close}, nil
	}
}

func (view *rootFSView) applyTar(input io.Reader, layer bool) error {
	reader := tar.NewReader(input)
	var pending []pendingHardLink
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		name, err := normalizedRootFSPath(header.Name)
		if err != nil {
			return err
		}
		if layer && view.applyWhiteout(name) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if existing, ok := view.entries[name]; ok && existing.kind != rootFSEntryDirectory {
				view.removePath(name)
			}
			view.entries[name] = rootFSEntry{kind: rootFSEntryDirectory, mode: header.Mode}
		case tar.TypeReg, 0:
			view.removePath(name)
			hash := sha256.New()
			var retained bytes.Buffer
			writer := io.Writer(hash)
			if name == manifestWallPath {
				writer = io.MultiWriter(hash, &retained)
			}
			// #nosec G110 -- test inputs are immutable digest-pinned image layers or bounded synthetic tar entries.
			written, err := io.Copy(writer, reader)
			if err != nil {
				return fmt.Errorf("read tar entry %q: %w", name, err)
			}
			if written != header.Size {
				return fmt.Errorf("tar entry %q yielded %d bytes, expected %d", name, written, header.Size)
			}
			view.entries[name] = rootFSEntry{
				kind:     rootFSEntryRegular,
				mode:     header.Mode,
				size:     written,
				digest:   hex.EncodeToString(hash.Sum(nil)),
				identity: view.allocateIdentity(),
				data:     bytes.Clone(retained.Bytes()),
			}
		case tar.TypeSymlink:
			view.removePath(name)
			view.entries[name] = rootFSEntry{
				kind:       rootFSEntrySymlink,
				mode:       header.Mode,
				linkTarget: header.Linkname,
				identity:   view.allocateIdentity(),
			}
		case tar.TypeLink:
			target, err := normalizedRootFSPath(header.Linkname)
			if err != nil {
				return fmt.Errorf("hard link %q: %w", name, err)
			}
			view.removePath(name)
			if !view.copyHardLink(name, target) {
				pending = append(pending, pendingHardLink{name: name, target: target})
			}
		case tar.TypeXGlobalHeader, tar.TypeXHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
			continue
		default:
			view.removePath(name)
			view.entries[name] = rootFSEntry{kind: rootFSEntryOther, mode: header.Mode, identity: view.allocateIdentity()}
		}
	}

	for len(pending) > 0 {
		unresolved := pending[:0]
		resolved := 0
		for _, link := range pending {
			if view.copyHardLink(link.name, link.target) {
				resolved++
			} else {
				unresolved = append(unresolved, link)
			}
		}
		if resolved == 0 {
			return fmt.Errorf("tar contains unresolved hard link %q to %q", unresolved[0].name, unresolved[0].target)
		}
		pending = unresolved
	}
	return nil
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
	entry.data = bytes.Clone(entry.data)
	view.entries[name] = entry
	return true
}

func (view *rootFSView) applyWhiteout(name string) bool {
	base := path.Base(name)
	if base == ".wh..wh..opq" {
		directory := path.Dir(name)
		prefix := directory + "/"
		if directory == "." {
			prefix = ""
		}
		for candidate := range view.entries {
			if candidate != directory && strings.HasPrefix(candidate, prefix) {
				delete(view.entries, candidate)
			}
		}
		return true
	}
	if !strings.HasPrefix(base, ".wh.") {
		return false
	}
	target := path.Join(path.Dir(name), strings.TrimPrefix(base, ".wh."))
	view.removePath(target)
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

func normalizedRootFSPath(value string) (string, error) {
	value = strings.TrimPrefix(strings.ReplaceAll(value, "\\", "/"), "./")
	value = strings.TrimPrefix(value, "/")
	cleaned := path.Clean(value)
	if cleaned == "" {
		cleaned = "."
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("tar path %q escapes the rootfs", value)
	}
	return cleaned, nil
}

func assertManifestMatchesRootFSTar(t *testing.T, manifest *copachisel.Manifest, tarPath string) {
	t.Helper()
	assertManifestMatchesRootFSView(t, manifest, rootFSViewFromTar(t, tarPath))
}

func assertManifestMatchesRootFSView(t *testing.T, manifest *copachisel.Manifest, view *rootFSView) {
	t.Helper()
	require.NotNil(t, manifest)
	require.NotNil(t, view)

	paths := make([]string, 0, len(manifest.OwnedPaths))
	for manifestPath := range manifest.OwnedPaths {
		paths = append(paths, manifestPath)
	}
	sort.Strings(paths)

	hardLinks := make(map[uint64][]uint64)
	for _, manifestPath := range paths {
		metadata := manifest.OwnedPaths[manifestPath]
		name, err := normalizedRootFSPath(manifestPath)
		require.NoError(t, err)
		entry, ok := view.entries[name]
		require.True(t, ok, "manifest-owned path %s is missing from the rootfs", manifestPath)
		require.Equalf(t, int64(metadata.Mode)&0o7777, entry.mode&0o7777, "mode mismatch for %s", manifestPath)

		switch {
		case metadata.IsDir():
			require.Equal(t, rootFSEntryDirectory, entry.kind, "manifest-owned path %s is not a directory", manifestPath)
		case metadata.IsSymlink():
			require.Equal(t, rootFSEntrySymlink, entry.kind, "manifest-owned path %s is not a symlink", manifestPath)
			require.Equal(t, metadata.Link, entry.linkTarget, "symlink target mismatch for %s", manifestPath)
		case metadata.IsRegular():
			require.Equal(t, rootFSEntryRegular, entry.kind, "manifest-owned path %s is not a regular file", manifestPath)
			digest := metadata.Digest()
			if metadata.Size != 0 || digest != "" {
				require.GreaterOrEqual(t, entry.size, int64(0), "negative rootfs size for %s", manifestPath)
				require.Equal(t, metadata.Size, uint64(entry.size), "size mismatch for %s", manifestPath) // #nosec G115 -- non-negative size checked above.
			}
			if digest != "" {
				require.Equal(t, strings.ToLower(digest), strings.ToLower(entry.digest), "digest mismatch for %s", manifestPath)
			}
		default:
			t.Fatalf("manifest-owned path %s has unknown type", manifestPath)
		}

		if metadata.Inode != 0 {
			require.NotZero(t, entry.identity, "hard-link path %s has no rootfs identity", manifestPath)
			hardLinks[metadata.Inode] = append(hardLinks[metadata.Inode], entry.identity)
		}
	}

	actualGroups := make(map[uint64]uint64)
	for manifestInode, identities := range hardLinks {
		require.GreaterOrEqual(t, len(identities), 2, "manifest hard-link group %d has fewer than two paths", manifestInode)
		for _, identity := range identities[1:] {
			require.Equal(t, identities[0], identity, "manifest hard-link group %d does not share one rootfs identity", manifestInode)
		}
		if previous, exists := actualGroups[identities[0]]; exists {
			require.Equal(t, previous, manifestInode, "distinct manifest hard-link groups share one rootfs identity")
		}
		actualGroups[identities[0]] = manifestInode
	}
}

func TestIndependentManifestRootFSValidation(t *testing.T) {
	const symlinkTarget = "file"
	content := []byte("managed content")
	digest := sha256.Sum256(content)
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	writeTarEntry(t, writer, &tar.Header{Name: "managed", Typeflag: tar.TypeDir, Mode: 0o755})
	writeTarEntry(t, writer, &tar.Header{Name: "managed/file", Typeflag: tar.TypeReg, Mode: 0o640, Size: int64(len(content))}, content)
	writeTarEntry(t, writer, &tar.Header{Name: "managed/file-hardlink", Typeflag: tar.TypeLink, Mode: 0o640, Linkname: "managed/file"})
	writeTarEntry(t, writer, &tar.Header{Name: "managed/symlink", Typeflag: tar.TypeSymlink, Mode: 0o777, Linkname: symlinkTarget})
	writeTarEntry(t, writer, &tar.Header{Name: "managed/symlink-hardlink", Typeflag: tar.TypeLink, Mode: 0o777, Linkname: "managed/symlink"})
	require.NoError(t, writer.Close())

	view := newRootFSView()
	require.NoError(t, view.applyTar(bytes.NewReader(archive.Bytes()), false))
	manifest := &copachisel.Manifest{OwnedPaths: map[string]copachisel.PathMetadata{
		"/managed/":                 {Path: "/managed/", Mode: 0o755},
		"/managed/file":             {Path: "/managed/file", Mode: 0o640, SHA256: hex.EncodeToString(digest[:]), Size: uint64(len(content)), Inode: 1},
		"/managed/file-hardlink":    {Path: "/managed/file-hardlink", Mode: 0o640, SHA256: hex.EncodeToString(digest[:]), Size: uint64(len(content)), Inode: 1},
		"/managed/symlink":          {Path: "/managed/symlink", Mode: 0o777, Link: symlinkTarget, Inode: 2},
		"/managed/symlink-hardlink": {Path: "/managed/symlink-hardlink", Mode: 0o777, Link: symlinkTarget, Inode: 2},
	}}
	assertManifestMatchesRootFSView(t, manifest, view)
}

func writeTarEntry(t *testing.T, writer *tar.Writer, header *tar.Header, content ...[]byte) {
	t.Helper()
	require.NoError(t, writer.WriteHeader(header))
	if len(content) != 0 {
		_, err := writer.Write(content[0])
		require.NoError(t, err)
	}
}
