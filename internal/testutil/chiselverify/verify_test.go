package chiselverify

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	copachisel "github.com/project-copacetic/copacetic/pkg/chisel"
	"github.com/stretchr/testify/require"
)

const (
	managedContent    = "managed content"
	managedFilePath   = "managed/file"
	managedLinkTarget = "file"
)

type rootFSTarOptions struct {
	brokenFileHardLink bool
	fileAsSymlink      bool
	omitPath           string
	symlinkTarget      string
}

func TestVerifyTar(t *testing.T) {
	manifest := validManifest()
	require.NoError(t, VerifyTar(manifest, bytes.NewReader(validRootFSTar(t, rootFSTarOptions{}))))
}

func TestVerifyTarAcceptsUnmeasuredRegularFile(t *testing.T) {
	manifest := &copachisel.Manifest{OwnedPaths: map[string]copachisel.PathMetadata{
		"/var/lib/chisel/manifest.wall": {
			Path: "/var/lib/chisel/manifest.wall",
			Mode: 0o644,
		},
	}}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	contents := []byte("self-referential manifest contents")
	require.NoError(t, writer.WriteHeader(&tar.Header{
		Name: "var/lib/chisel/manifest.wall", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(contents)),
	}))
	_, err := writer.Write(contents)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	require.NoError(t, VerifyTar(manifest, bytes.NewReader(archive.Bytes())))
}

func TestVerifyTarFailures(t *testing.T) {
	tests := []struct {
		name           string
		mutateManifest func(*copachisel.Manifest)
		tarOptions     rootFSTarOptions
		wantError      string
	}{
		{
			name:       "wrong type",
			tarOptions: rootFSTarOptions{fileAsSymlink: true},
			wantError:  `path "/managed/file" is a symbolic link in the rootfs; expected regular file`,
		},
		{
			name: "wrong digest",
			mutateManifest: func(manifest *copachisel.Manifest) {
				metadata := manifest.OwnedPaths["/managed/file"]
				metadata.FinalSHA256 = strings.Repeat("a", 64)
				manifest.OwnedPaths[metadata.Path] = metadata
			},
			wantError: `regular file "/managed/file" has sha256`,
		},
		{
			name: "wrong size",
			mutateManifest: func(manifest *copachisel.Manifest) {
				metadata := manifest.OwnedPaths["/managed/file"]
				metadata.Size++
				manifest.OwnedPaths[metadata.Path] = metadata
			},
			wantError: `regular file "/managed/file" has size`,
		},
		{
			name: "wrong mode",
			mutateManifest: func(manifest *copachisel.Manifest) {
				metadata := manifest.OwnedPaths["/managed/file"]
				metadata.Mode = 0o600
				manifest.OwnedPaths[metadata.Path] = metadata
			},
			wantError: `path "/managed/file" has mode 0640; expected 0600`,
		},
		{
			name:       "wrong symlink target",
			tarOptions: rootFSTarOptions{symlinkTarget: "unexpected"},
			wantError:  `symbolic link "/managed/symlink" targets "unexpected"; expected "file"`,
		},
		{
			name:       "missing path",
			tarOptions: rootFSTarOptions{omitPath: "managed"},
			wantError:  `path "/managed/" is missing from the rootfs`,
		},
		{
			name:       "broken hard-link identity",
			tarOptions: rootFSTarOptions{brokenFileHardLink: true},
			wantError:  `hard-link group 1 is broken`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest()
			if test.mutateManifest != nil {
				test.mutateManifest(manifest)
			}
			err := VerifyTar(manifest, bytes.NewReader(validRootFSTar(t, test.tarOptions)))
			require.ErrorContains(t, err, test.wantError)
		})
	}
}

func validManifest() *copachisel.Manifest {
	content := []byte(managedContent)
	finalDigest := sha256.Sum256(content)
	return &copachisel.Manifest{OwnedPaths: map[string]copachisel.PathMetadata{
		"/managed/": {
			Path: "/managed/",
			Mode: 0o755,
		},
		"/managed/file": {
			Path:        "/managed/file",
			Mode:        0o640,
			SHA256:      strings.Repeat("0", 64),
			FinalSHA256: hex.EncodeToString(finalDigest[:]),
			Size:        uint64(len(content)),
			Inode:       1,
		},
		"/managed/file-hardlink": {
			Path:        "/managed/file-hardlink",
			Mode:        0o640,
			SHA256:      strings.Repeat("0", 64),
			FinalSHA256: hex.EncodeToString(finalDigest[:]),
			Size:        uint64(len(content)),
			Inode:       1,
		},
		"/managed/symlink": {
			Path:  "/managed/symlink",
			Mode:  0o777,
			Link:  managedLinkTarget,
			Inode: 2,
		},
		"/managed/symlink-hardlink": {
			Path:  "/managed/symlink-hardlink",
			Mode:  0o777,
			Link:  managedLinkTarget,
			Inode: 2,
		},
	}}
}

func validRootFSTar(t *testing.T, options rootFSTarOptions) []byte {
	t.Helper()
	if options.symlinkTarget == "" {
		options.symlinkTarget = managedLinkTarget
	}

	content := []byte(managedContent)
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	writeEntry := func(header *tar.Header, data []byte) {
		t.Helper()
		if header.Name == options.omitPath {
			return
		}
		require.NoError(t, writer.WriteHeader(header))
		if len(data) != 0 {
			_, err := writer.Write(data)
			require.NoError(t, err)
		}
	}

	writeEntry(&tar.Header{Name: "managed", Typeflag: tar.TypeDir, Mode: 0o755}, nil)
	if options.fileAsSymlink {
		writeEntry(&tar.Header{Name: managedFilePath, Typeflag: tar.TypeSymlink, Mode: 0o640, Linkname: "unexpected"}, nil)
	} else {
		writeEntry(&tar.Header{Name: managedFilePath, Typeflag: tar.TypeReg, Mode: 0o640, Size: int64(len(content))}, content)
	}
	if options.brokenFileHardLink {
		writeEntry(&tar.Header{Name: "managed/file-hardlink", Typeflag: tar.TypeReg, Mode: 0o640, Size: int64(len(content))}, content)
	} else {
		writeEntry(&tar.Header{Name: "managed/file-hardlink", Typeflag: tar.TypeLink, Mode: 0o640, Linkname: managedFilePath}, nil)
	}
	writeEntry(&tar.Header{Name: "managed/symlink", Typeflag: tar.TypeSymlink, Mode: 0o777, Linkname: options.symlinkTarget}, nil)
	writeEntry(&tar.Header{Name: "managed/symlink-hardlink", Typeflag: tar.TypeLink, Mode: 0o777, Linkname: "managed/symlink"}, nil)
	require.NoError(t, writer.Close())
	return archive.Bytes()
}
