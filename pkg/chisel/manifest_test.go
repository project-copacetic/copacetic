package chisel

import (
	"bytes"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	digestA                         = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB                         = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	digestC                         = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	digestD                         = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	digestE                         = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	inconsistentHardLinkMetadataErr = "have inconsistent metadata"
)

type jsonWallOptions struct {
	version       string
	schema        string
	count         int
	preserveOrder bool
}

func TestParseManifest(t *testing.T) {
	compressed := compressJSONWall(t, validManifestRecords(), jsonWallOptions{})

	parsed, err := ParseManifest(bytes.NewReader(compressed))
	require.NoError(t, err)

	require.Len(t, parsed.Packages, 2)
	assert.Equal(t, Package{
		Name:         "base-files",
		Version:      "13ubuntu10.2",
		SHA256:       digestD,
		Architecture: ociArchAMD64,
	}, parsed.Packages["base-files"])
	assert.Equal(t, "2.39-0ubuntu8.4", parsed.Packages["libc6"].Version)
	assert.Equal(t, []string{"base-files_base", "base-files_manifest", "libc6_libs"}, parsed.Slices)

	require.Len(t, parsed.OwnedPaths, 6)
	osRelease := parsed.OwnedPaths["/etc/os-release"]
	assert.Equal(t, fs.FileMode(0o644), osRelease.Mode)
	assert.Equal(t, []string{"base-files_base"}, osRelease.Slices)
	assert.Equal(t, digestB, osRelease.Digest())
	assert.True(t, osRelease.IsRegular())
	assert.False(t, osRelease.IsDir())
	assert.False(t, osRelease.IsSymlink())

	directory := parsed.OwnedPaths["/etc/"]
	assert.True(t, directory.IsDir())
	assert.Equal(t, fs.FileMode(0o755), directory.Mode)

	symlink := parsed.OwnedPaths["/usr/lib/libc.so"]
	assert.True(t, symlink.IsSymlink())
	assert.Equal(t, "libc.so.6", symlink.Link)

	hardLink := parsed.OwnedPaths["/usr/lib/libc-hardlink.so.6"]
	assert.Equal(t, uint64(1), hardLink.Inode)
	assert.Equal(t, digestC, hardLink.Digest())
}

func TestParseManifestAcceptsHardLinkedSymlinks(t *testing.T) {
	compressed := compressJSONWall(t, manifestRecordsWithSymlinkHardLinks(t), jsonWallOptions{})

	parsed, err := ParseManifest(bytes.NewReader(compressed))
	require.NoError(t, err)

	first := parsed.OwnedPaths["/usr/lib/libc.so"]
	second := parsed.OwnedPaths["/usr/lib/libc-link.so"]
	assert.True(t, first.IsSymlink())
	assert.True(t, second.IsSymlink())
	assert.Equal(t, uint64(2), first.Inode)
	assert.Equal(t, first.Inode, second.Inode)
	assert.Equal(t, first.Mode, second.Mode)
	assert.Equal(t, first.Link, second.Link)
}

func TestParseManifestRejectsInconsistentSymlinkHardLinkGroups(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(*testing.T, []string)
		errContains string
	}{
		{
			name: "mixed path kinds",
			modify: func(t *testing.T, records []string) {
				replaceRecord(t, records, `"kind":"path","path":"/usr/lib/libc-link.so"`, func(record string) string {
					return strings.Replace(
						record,
						`,"link":"libc.so.6"`,
						fmt.Sprintf(`,"sha256":"%s","size":3`, digestC),
						1,
					)
				})
			},
			errContains: "mixes regular and symlink paths",
		},
		{
			name: "different link targets",
			modify: func(t *testing.T, records []string) {
				replaceRecord(t, records, `"kind":"path","path":"/usr/lib/libc-link.so"`, func(record string) string {
					return strings.Replace(record, `"link":"libc.so.6"`, `"link":"libc.so.5"`, 1)
				})
			},
			errContains: inconsistentHardLinkMetadataErr,
		},
		{
			name: "different modes",
			modify: func(t *testing.T, records []string) {
				replaceRecord(t, records, `"kind":"path","path":"/usr/lib/libc-link.so"`, func(record string) string {
					return strings.Replace(record, `"mode":"0777"`, `"mode":"0755"`, 1)
				})
			},
			errContains: inconsistentHardLinkMetadataErr,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			records := manifestRecordsWithSymlinkHardLinks(t)
			test.modify(t, records)

			_, err := ParseManifest(bytes.NewReader(compressJSONWall(t, records, jsonWallOptions{})))
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.errContains)
		})
	}
}

func TestParseManifestAcceptsSchemaOneAdditiveFieldsAndJSONWallMinorVersion(t *testing.T) {
	records := validManifestRecords()
	replaceRecord(t, records, `"kind":"package","name":"base-files"`, func(record string) string {
		return strings.TrimSuffix(record, "}") + `,"future":{"accepted":true}}`
	})
	compressed := compressJSONWall(t, records, jsonWallOptions{version: "1.7"})

	parsed, err := ParseManifest(bytes.NewReader(compressed))
	require.NoError(t, err)
	assert.Equal(t, "13ubuntu10.2", parsed.Packages["base-files"].Version)
}

func TestParseManifestRejectsMalformedInput(t *testing.T) {
	tests := []struct {
		name        string
		modify      func(*testing.T, []string) []string
		options     jsonWallOptions
		errContains string
	}{
		{
			name:        "unsupported JSONWall major version",
			options:     jsonWallOptions{version: "2.0"},
			errContains: "unsupported JSONWall version",
		},
		{
			name:        "unsupported schema",
			options:     jsonWallOptions{schema: "2.0"},
			errContains: "unsupported Chisel manifest schema",
		},
		{
			name:        "incorrect record count",
			options:     jsonWallOptions{count: 999},
			errContains: "header count is 999",
		},
		{
			name: "malformed record",
			modify: func(_ *testing.T, records []string) []string {
				records = append(records, `{"kind":"package","name":`)
				return records
			},
			errContains: "cannot decode JSONWall record",
		},
		{
			name: "unknown record kind",
			modify: func(_ *testing.T, records []string) []string {
				return append(records, `{"kind":"unknown","name":"future"}`)
			},
			errContains: `unsupported kind "unknown"`,
		},
		{
			name: "missing package version",
			modify: func(t *testing.T, records []string) []string {
				replaceRecord(t, records, `"kind":"package","name":"libc6"`, func(record string) string {
					return strings.Replace(record, `,"version":"2.39-0ubuntu8.4"`, "", 1)
				})
				return records
			},
			errContains: `package "libc6" is missing version`,
		},
		{
			name: "invalid package name",
			modify: func(t *testing.T, records []string) []string {
				replaceRecord(t, records, `"kind":"package","name":"libc6"`, func(record string) string {
					return strings.Replace(record, `"name":"libc6"`, `"name":"LibC"`, 1)
				})
				return records
			},
			errContains: `invalid Debian package name "LibC"`,
		},
		{
			name: "invalid slice name",
			modify: func(t *testing.T, records []string) []string {
				replaceRecord(t, records, `"kind":"slice","name":"libc6_libs"`, func(record string) string {
					return strings.Replace(record, `"libc6_libs"`, `"libc6_x"`, 1)
				})
				return records
			},
			errContains: `invalid Chisel slice name "libc6_x"`,
		},
		{
			name: "duplicate package",
			modify: func(t *testing.T, records []string) []string {
				return append(records, findRecord(t, records, `"kind":"package","name":"libc6"`))
			},
			errContains: `duplicate package record "libc6"`,
		},
		{
			name: "duplicate slice",
			modify: func(t *testing.T, records []string) []string {
				return append(records, findRecord(t, records, `"kind":"slice","name":"libc6_libs"`))
			},
			errContains: `duplicate slice record "libc6_libs"`,
		},
		{
			name: "duplicate path",
			modify: func(t *testing.T, records []string) []string {
				return append(records, findRecord(t, records, `"kind":"path","path":"/etc/os-release"`))
			},
			errContains: `duplicate path record "/etc/os-release"`,
		},
		{
			name: "duplicate content",
			modify: func(t *testing.T, records []string) []string {
				return append(records, findRecord(t, records, `"kind":"content","slice":"base-files_base","path":"/etc/os-release"`))
			},
			errContains: "duplicate content record",
		},
		{
			name: "relative path",
			modify: func(t *testing.T, records []string) []string {
				replaceAllRecords(records, `/etc/os-release`, `etc/os-release`)
				return records
			},
			errContains: "path must be absolute",
		},
		{
			name: "path traversal",
			modify: func(t *testing.T, records []string) []string {
				replaceAllRecords(records, `/etc/os-release`, `/etc/../tmp/owned`)
				return records
			},
			errContains: "must not contain traversal",
		},
		{
			name: "non-normalized path",
			modify: func(t *testing.T, records []string) []string {
				replaceAllRecords(records, `/etc/os-release`, `/etc//os-release`)
				return records
			},
			errContains: "must be normalized",
		},
		{
			name: "slice refers to missing package",
			modify: func(t *testing.T, records []string) []string {
				return removeRecord(t, records, `"kind":"package","name":"libc6"`)
			},
			errContains: `slice "libc6_libs" refers to missing package "libc6"`,
		},
		{
			name: "content refers to missing slice",
			modify: func(t *testing.T, records []string) []string {
				return removeRecord(t, records, `"kind":"slice","name":"libc6_libs"`)
			},
			errContains: "refers to missing slice",
		},
		{
			name: "content has no path",
			modify: func(t *testing.T, records []string) []string {
				return removeRecord(t, records, `"kind":"path","path":"/etc/os-release"`)
			},
			errContains: `content path "/etc/os-release" has no matching path record`,
		},
		{
			name: "path has no content",
			modify: func(t *testing.T, records []string) []string {
				return removeRecord(t, records, `"kind":"content","slice":"base-files_base","path":"/etc/os-release"`)
			},
			errContains: `path "/etc/os-release" has no matching content record`,
		},
		{
			name: "content and path slices diverge",
			modify: func(t *testing.T, records []string) []string {
				replaceRecord(t, records, `"kind":"path","path":"/etc/os-release"`, func(record string) string {
					return strings.Replace(record, `"slices":["base-files_base"]`, `"slices":["base-files_manifest"]`, 1)
				})
				return records
			},
			errContains: "refer to different slices",
		},
		{
			name: "singleton hard-link group",
			modify: func(t *testing.T, records []string) []string {
				replaceRecord(t, records, `"kind":"path","path":"/usr/lib/libc.so.6"`, func(record string) string {
					return strings.Replace(record, `,"inode":1`, "", 1)
				})
				return records
			},
			errContains: "hard-link group 1 contains only path",
		},
		{
			name: "non-contiguous hard-link groups",
			modify: func(t *testing.T, records []string) []string {
				for index := range records {
					if strings.Contains(records[index], `"kind":"path"`) && strings.Contains(records[index], `,"inode":1`) {
						records[index] = strings.Replace(records[index], `,"inode":1`, `,"inode":2`, 1)
					}
				}
				return records
			},
			errContains: "hard-link group 1 is missing before group 2",
		},
		{
			name: "inconsistent hard-link metadata",
			modify: func(t *testing.T, records []string) []string {
				replaceRecord(t, records, `"kind":"path","path":"/usr/lib/libc.so.6"`, func(record string) string {
					return strings.Replace(record, digestC, digestE, 1)
				})
				return records
			},
			errContains: inconsistentHardLinkMetadataErr,
		},
		{
			name: "unsorted JSONWall",
			modify: func(_ *testing.T, records []string) []string {
				sort.Sort(sort.Reverse(sort.StringSlice(records)))
				return records
			},
			options:     jsonWallOptions{preserveOrder: true},
			errContains: "are not sorted",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			records := validManifestRecords()
			if test.modify != nil {
				records = test.modify(t, records)
			}
			compressed := compressJSONWall(t, records, test.options)

			_, err := ParseManifest(bytes.NewReader(compressed))
			require.Error(t, err)
			assert.Contains(t, err.Error(), test.errContains)
		})
	}
}

func TestParseManifestRejectsExcessiveRecordCounts(t *testing.T) {
	t.Run("declared count", func(t *testing.T) {
		compressed := compressJSONWall(t, validManifestRecords(), jsonWallOptions{count: maxManifestRecords + 1})

		_, err := ParseManifest(bytes.NewReader(compressed))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "header record count")
		assert.Contains(t, err.Error(), "structural limit")
	})

	t.Run("physical count", func(t *testing.T) {
		compressed := compressManySliceRecords(t, maxManifestRecords, maxManifestRecords)
		decompressed, err := decompressManifest(bytes.NewReader(compressed))
		require.NoError(t, err)
		require.Less(t, len(decompressed), MaxManifestSize)

		_, err = ParseManifest(bytes.NewReader(compressed))
		require.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("contains %d JSONWall records", maxManifestRecords+1))
		assert.Contains(t, err.Error(), "structural limit")
	})
}

func TestParseManifestRejectsNonZstdInput(t *testing.T) {
	_, err := ParseManifest(strings.NewReader("not zstd"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decompress")
}

func TestParseManifestBoundsDecompressedSize(t *testing.T) {
	var compressed bytes.Buffer
	writer, err := zstd.NewWriter(&compressed, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1))
	require.NoError(t, err)
	chunk := bytes.Repeat([]byte{'x'}, 1<<20)
	for range MaxManifestSize / len(chunk) {
		_, err = writer.Write(chunk)
		require.NoError(t, err)
	}
	_, err = writer.Write([]byte{'x'})
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	_, err = ParseManifest(bytes.NewReader(compressed.Bytes()))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the 64 MiB decompressed size limit")
}

func BenchmarkParseManifest(b *testing.B) {
	compressed := compressJSONWall(b, validManifestRecords(), jsonWallOptions{})
	b.ReportAllocs()
	b.SetBytes(int64(len(compressed)))
	for range b.N {
		if _, err := ParseManifest(bytes.NewReader(compressed)); err != nil {
			b.Fatal(err)
		}
	}
}

func validManifestRecords() []string {
	return []string{
		fmt.Sprintf(`{"kind":"package","name":"base-files","version":"13ubuntu10.2","sha256":"%s","arch":"%s"}`, digestD, ociArchAMD64),
		fmt.Sprintf(`{"kind":"package","name":"libc6","version":"2.39-0ubuntu8.4","sha256":"%s","arch":"%s"}`, digestE, ociArchAMD64),
		`{"kind":"slice","name":"base-files_base"}`,
		`{"kind":"slice","name":"base-files_manifest"}`,
		`{"kind":"slice","name":"libc6_libs"}`,
		`{"kind":"content","slice":"base-files_manifest","path":"/chisel/manifest.wall"}`,
		`{"kind":"content","slice":"base-files_base","path":"/etc/"}`,
		`{"kind":"content","slice":"base-files_base","path":"/etc/os-release"}`,
		`{"kind":"content","slice":"libc6_libs","path":"/usr/lib/libc-hardlink.so.6"}`,
		`{"kind":"content","slice":"libc6_libs","path":"/usr/lib/libc.so"}`,
		`{"kind":"content","slice":"libc6_libs","path":"/usr/lib/libc.so.6"}`,
		`{"kind":"path","path":"/chisel/manifest.wall","mode":"0644","slices":["base-files_manifest"]}`,
		`{"kind":"path","path":"/etc/","mode":"0755","slices":["base-files_base"]}`,
		fmt.Sprintf(`{"kind":"path","path":"/etc/os-release","mode":"0644","slices":["base-files_base"],"sha256":"%s","final_sha256":"%s","size":12}`, digestA, digestB),
		fmt.Sprintf(`{"kind":"path","path":"/usr/lib/libc-hardlink.so.6","mode":"0644","slices":["libc6_libs"],"sha256":"%s","size":3,"inode":1}`, digestC),
		`{"kind":"path","path":"/usr/lib/libc.so","mode":"0777","slices":["libc6_libs"],"link":"libc.so.6"}`,
		fmt.Sprintf(`{"kind":"path","path":"/usr/lib/libc.so.6","mode":"0644","slices":["libc6_libs"],"sha256":"%s","size":3,"inode":1}`, digestC),
	}
}

func manifestRecordsWithSymlinkHardLinks(t *testing.T) []string {
	t.Helper()
	records := validManifestRecords()
	replaceRecord(t, records, `"kind":"path","path":"/usr/lib/libc.so"`, func(record string) string {
		return strings.TrimSuffix(record, "}") + `,"inode":2}`
	})
	records = append(records,
		`{"kind":"content","slice":"libc6_libs","path":"/usr/lib/libc-link.so"}`,
		`{"kind":"path","path":"/usr/lib/libc-link.so","mode":"0777","slices":["libc6_libs"],"link":"libc.so.6","inode":2}`,
	)
	return records
}

func compressManySliceRecords(tb testing.TB, records, declaredCount int) []byte {
	tb.Helper()

	var raw bytes.Buffer
	fmt.Fprintf(&raw, `{"jsonwall":"1.0","schema":"1.0","count":%d}`+"\n", declaredCount)
	for index := range records {
		fmt.Fprintf(&raw, `{"kind":"slice","name":"pkg%05d_slice"}`+"\n", index)
	}
	return compressJSONWallBytes(tb, raw.Bytes())
}

func compressJSONWall(tb testing.TB, records []string, options jsonWallOptions) []byte {
	tb.Helper()
	version := options.version
	if version == "" {
		version = "1.0"
	}
	schema := options.schema
	if schema == "" {
		schema = "1.0"
	}
	if !options.preserveOrder {
		sort.Strings(records)
	}
	count := options.count
	if count == 0 {
		count = len(records) + 1
	}

	var raw bytes.Buffer
	fmt.Fprintf(&raw, `{"jsonwall":%q,"schema":%q,"count":%d}`+"\n", version, schema, count)
	for _, record := range records {
		raw.WriteString(record)
		raw.WriteByte('\n')
	}

	return compressJSONWallBytes(tb, raw.Bytes())
}

func compressJSONWallBytes(tb testing.TB, raw []byte) []byte {
	tb.Helper()

	var compressed bytes.Buffer
	writer, err := zstd.NewWriter(&compressed, zstd.WithEncoderConcurrency(1))
	require.NoError(tb, err)
	_, err = writer.Write(raw)
	require.NoError(tb, err)
	require.NoError(tb, writer.Close())
	return compressed.Bytes()
}

func findRecord(t *testing.T, records []string, substring string) string {
	t.Helper()
	for _, record := range records {
		if strings.Contains(record, substring) {
			return record
		}
	}
	t.Fatalf("record containing %q not found", substring)
	return ""
}

func replaceRecord(t *testing.T, records []string, substring string, replace func(string) string) {
	t.Helper()
	for index := range records {
		if strings.Contains(records[index], substring) {
			records[index] = replace(records[index])
			return
		}
	}
	t.Fatalf("record containing %q not found", substring)
}

func removeRecord(t *testing.T, records []string, substring string) []string {
	t.Helper()
	for index := range records {
		if strings.Contains(records[index], substring) {
			return append(records[:index], records[index+1:]...)
		}
	}
	t.Fatalf("record containing %q not found", substring)
	return nil
}

func replaceAllRecords(records []string, oldValue, newValue string) {
	for index := range records {
		records[index] = strings.ReplaceAll(records[index], oldValue, newValue)
	}
}
