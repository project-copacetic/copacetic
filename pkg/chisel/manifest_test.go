package chisel

import (
	"bytes"
	"encoding/json"
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
	headerFields  string
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
		return appendRecordFields(record, `,"future":{"accepted":true}`)
	})
	compressed := compressJSONWall(t, records, jsonWallOptions{
		version:      "1.7",
		headerFields: `,"future":{"accepted":true}`,
	})

	parsed, err := ParseManifest(bytes.NewReader(compressed))
	require.NoError(t, err)
	assert.Equal(t, "13ubuntu10.2", parsed.Packages["base-files"].Version)
}

func TestParseManifestRejectsDuplicateHeaderFields(t *testing.T) {
	recordCount := len(validManifestRecords()) + 1
	tests := []struct {
		name         string
		headerFields string
		field        string
		alias        string
	}{
		{name: "same count", headerFields: fmt.Sprintf(`,"count":%d`, recordCount), field: "count"},
		{name: "conflicting count", headerFields: `,"count":999`, field: "count"},
		{name: "case-folded count", headerFields: fmt.Sprintf(`,"Count":%d`, recordCount), field: "count", alias: "Count"},
		{name: "same schema", headerFields: `,"schema":"1.0"`, field: "schema"},
		{name: "conflicting schema", headerFields: `,"schema":"2.0"`, field: "schema"},
		{name: "same JSONWall version", headerFields: `,"jsonwall":"1.0"`, field: "jsonwall"},
		{name: "conflicting JSONWall version", headerFields: `,"jsonwall":"2.0"`, field: "jsonwall"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compressed := compressJSONWall(t, validManifestRecords(), jsonWallOptions{headerFields: test.headerFields})

			_, err := ParseManifest(bytes.NewReader(compressed))
			require.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf(`duplicate JSON field %q`, test.field))
			if test.alias != "" {
				assert.Contains(t, err.Error(), fmt.Sprintf(`case-insensitive alias %q`, test.alias))
			}
		})
	}
}

func TestParseManifestRejectsDuplicateRecordFields(t *testing.T) {
	tests := []struct {
		name   string
		record string
		fields string
		field  string
		alias  string
	}{
		{name: "same kind", record: `"kind":"package","name":"base-files"`, fields: `,"kind":"package"`, field: "kind"},
		{name: "conflicting kind", record: `"kind":"package","name":"base-files"`, fields: `,"kind":"slice"`, field: "kind"},
		{name: "case-folded kind", record: `"kind":"package","name":"base-files"`, fields: `,"Kind":"slice"`, field: "kind", alias: "Kind"},
		{name: "Unicode case-folded kind", record: `"kind":"package","name":"base-files"`, fields: `,"\u212Aind":"slice"`, field: "kind", alias: "Kind"},
		{name: "same path", record: `"kind":"content","slice":"base-files_base","path":"/etc/os-release"`, fields: `,"path":"/etc/os-release"`, field: "path"},
		{name: "conflicting path", record: `"kind":"content","slice":"base-files_base","path":"/etc/os-release"`, fields: `,"path":"/tmp/other"`, field: "path"},
		{name: "case-folded path", record: `"kind":"content","slice":"base-files_base","path":"/etc/os-release"`, fields: `,"Path":"/tmp/other"`, field: "path", alias: "Path"},
		{name: "same name", record: `"kind":"package","name":"base-files"`, fields: `,"name":"base-files"`, field: "name"},
		{name: "conflicting name", record: `"kind":"package","name":"base-files"`, fields: `,"name":"libc6"`, field: "name"},
		{name: "same sha256", record: `"kind":"package","name":"base-files"`, fields: fmt.Sprintf(`,"sha256":"%s"`, digestD), field: "sha256"},
		{name: "conflicting sha256", record: `"kind":"package","name":"base-files"`, fields: fmt.Sprintf(`,"sha256":"%s"`, digestE), field: "sha256"},
		{name: "same mode", record: `"kind":"path","path":"/etc/os-release"`, fields: `,"mode":"0644"`, field: "mode"},
		{name: "conflicting mode", record: `"kind":"path","path":"/etc/os-release"`, fields: `,"mode":"0755"`, field: "mode"},
		{name: "same slices", record: `"kind":"path","path":"/etc/os-release"`, fields: `,"slices":["base-files_base"]`, field: "slices"},
		{name: "conflicting slices", record: `"kind":"path","path":"/etc/os-release"`, fields: `,"slices":["base-files_manifest"]`, field: "slices"},
		{name: "case-folded slices", record: `"kind":"path","path":"/etc/os-release"`, fields: `,"Slices":["base-files_manifest"]`, field: "slices", alias: "Slices"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			records := validManifestRecords()
			replaceRecord(t, records, test.record, func(record string) string {
				return appendRecordFields(record, test.fields)
			})

			_, err := ParseManifest(bytes.NewReader(compressJSONWall(t, records, jsonWallOptions{})))
			require.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf(`duplicate JSON field %q`, test.field))
			if test.alias != "" {
				assert.Contains(t, err.Error(), fmt.Sprintf(`case-insensitive alias %q`, test.alias))
			}
		})
	}
}

func TestParseManifestBoundsPathRecordSlices(t *testing.T) {
	const targetPath = "/usr/lib/libc.so.6"
	allSlices := []string{"base-files_base", "base-files_manifest", "libc6_libs"}

	manifestWithPathSlices := func(t *testing.T, fieldName string, pathSlices []string) []string {
		t.Helper()

		records := validManifestRecords()
		records = append(records,
			`{"kind":"content","slice":"base-files_base","path":"/usr/lib/libc.so.6"}`,
			`{"kind":"content","slice":"base-files_manifest","path":"/usr/lib/libc.so.6"}`,
		)

		encodedSlices, err := json.Marshal(pathSlices)
		require.NoError(t, err)
		replaceRecord(t, records, `"kind":"path","path":"/usr/lib/libc.so.6"`, func(record string) string {
			record = strings.Replace(record, `"slices":["libc6_libs"]`, fmt.Sprintf(`%q:%s`, fieldName, encodedSlices), 1)
			return appendRecordFields(record, `,"future":{"accepted":true}`)
		})
		return records
	}

	t.Run("at maximum possible slice records", func(t *testing.T) {
		records := manifestWithPathSlices(t, "slices", allSlices)

		parsed, err := ParseManifest(bytes.NewReader(compressJSONWall(t, records, jsonWallOptions{})))
		require.NoError(t, err)
		assert.Equal(t, allSlices, parsed.OwnedPaths[targetPath].Slices)
	})

	for _, fieldName := range []string{"slices", "Slices"} {
		t.Run("over maximum via "+fieldName, func(t *testing.T) {
			records := manifestWithPathSlices(t, fieldName, append(allSlices, "future_more"))

			_, err := ParseManifest(bytes.NewReader(compressJSONWall(t, records, jsonWallOptions{})))
			require.Error(t, err)
			assert.Contains(t, err.Error(), `path record "slices" array contains 4 entries`)
			assert.Contains(t, err.Error(), `at most 3 slice records can follow this path record`)
		})
	}
}

func TestParseManifestBoundsTopLevelJSONObjects(t *testing.T) {
	const (
		packageRecordMembers  = 5
		packageRecordKeyBytes = len("kind") + len("name") + len("version") + len("sha256") + len("arch")
	)

	parseWithPackageFields := func(t *testing.T, fields string) (*Manifest, error) {
		t.Helper()
		records := validManifestRecords()
		replaceRecord(t, records, `"kind":"package","name":"base-files"`, func(record string) string {
			return appendRecordFields(record, fields)
		})
		return ParseManifest(bytes.NewReader(compressJSONWall(t, records, jsonWallOptions{})))
	}

	t.Run("member count at limit", func(t *testing.T) {
		fields := additiveBooleanFields(maxJSONObjectMembers - packageRecordMembers)

		_, err := parseWithPackageFields(t, fields)
		require.NoError(t, err)
	})

	t.Run("member count over limit", func(t *testing.T) {
		fields := additiveBooleanFields(maxJSONObjectMembers - packageRecordMembers + 1)

		_, err := parseWithPackageFields(t, fields)
		require.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf(
			"top-level member count %d exceeds the structural limit of %d members",
			maxJSONObjectMembers+1,
			maxJSONObjectMembers,
		))
	})

	t.Run("key bytes at limit", func(t *testing.T) {
		field := strings.Repeat("x", maxJSONObjectKeyBytes-packageRecordKeyBytes)

		_, err := parseWithPackageFields(t, fmt.Sprintf(`,%q:true`, field))
		require.NoError(t, err)
	})

	t.Run("key bytes over limit", func(t *testing.T) {
		field := strings.Repeat("x", maxJSONObjectKeyBytes-packageRecordKeyBytes+1)

		_, err := parseWithPackageFields(t, fmt.Sprintf(`,%q:true`, field))
		require.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf(
			"field names use %d bytes, exceeding the structural limit of %d bytes",
			maxJSONObjectKeyBytes+1,
			maxJSONObjectKeyBytes,
		))
	})
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
	fmt.Fprintf(&raw, `{"jsonwall":%q,"schema":%q,"count":%d%s}`+"\n", version, schema, count, options.headerFields)
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

func additiveBooleanFields(count int) string {
	var fields strings.Builder
	for index := range count {
		fmt.Fprintf(&fields, `,"future%d":true`, index)
	}
	return fields.String()
}

func appendRecordFields(record, fields string) string {
	return strings.TrimSuffix(record, "}") + fields + "}"
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
