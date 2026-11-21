package buildkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const namedOCIExportOutput = "example.com/acme/app:1.0-patched"

// namedOCIExportResults returns patch results for a named image, as a
// multi-platform patch of a registry or daemon image produces them.
func namedOCIExportResults(t *testing.T, platforms []ispec.Platform) ([]types.PatchResult, []types.PatchPlatform) {
	t.Helper()
	original, err := reference.ParseNormalizedNamed("example.com/acme/app:1.0")
	require.NoError(t, err)
	results := make([]types.PatchResult, 0, len(platforms))
	patchPlatforms := make([]types.PatchPlatform, 0, len(platforms))
	for i := range platforms {
		patched, err := reference.ParseNormalizedNamed(namedOCIExportOutput + getPlatformSuffix(&platforms[i]))
		require.NoError(t, err)
		state := llb.Scratch()
		results = append(results, types.PatchResult{
			OriginalRef:  original,
			PatchedRef:   patched,
			PatchedState: &state,
			ConfigData:   mustMarshalJSON(t, ispec.Image{Platform: platforms[i], RootFS: ispec.RootFS{Type: "layers"}}),
		})
		patchPlatforms = append(patchPlatforms, types.PatchPlatform{Platform: platforms[i]})
	}
	return results, patchPlatforms
}

func namedOCIExportOptions(atomic bool) OCILayoutExportOptions {
	return OCILayoutExportOptions{
		Atomic:          atomic,
		OutputReference: namedOCIExportOutput,
		BuildkitOpts:    &Opts{Addr: "tcp://127.0.0.1:1"},
	}
}

// isolateTempDir points the process temporary directory at an empty directory,
// so a test can check that the export removed every directory it created there.
func isolateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	return dir
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

func dirEntryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func assertDirEmpty(t *testing.T, dir, msg string) {
	t.Helper()
	assert.Empty(t, dirEntryNames(t, dir), msg)
}

// assertNamedOCILayout checks that output holds a named export's layout, which
// lists each platform manifest in index.json itself.
func assertNamedOCILayout(t *testing.T, output string, platforms []ispec.Platform) {
	t.Helper()
	var index ispec.Index
	require.NoError(t, json.Unmarshal(mustReadFile(t, filepath.Join(output, ispec.ImageIndexFile)), &index))
	found := make([]ispec.Platform, 0, len(index.Manifests))
	for _, desc := range index.Manifests {
		require.NotNil(t, desc.Platform)
		found = append(found, *desc.Platform)
		assert.FileExists(t, filepath.Join(output, "blobs", desc.Digest.Algorithm().String(), desc.Digest.Encoded()))
	}
	assert.ElementsMatch(t, platforms, found)
	assert.FileExists(t, filepath.Join(output, ispec.ImageLayoutFile))
	assert.Equal(t, []string{"blobs", ispec.ImageIndexFile, ispec.ImageLayoutFile}, dirEntryNames(t, output),
		"no export tar or extraction directory may remain in the layout")
}

// stubSinglePlatformTempCheck wraps the stubbed fake exporter to check that a
// single-platform export writes its tar outside TMPDIR, so a small TMPDIR
// does not limit the image size.
func stubSinglePlatformTempCheck(t *testing.T, tmp string) {
	t.Helper()
	fake := buildOCIExport
	buildOCIExport = func(ctx context.Context, c *client.Client, solveOpt client.SolveOpt, build gwclient.BuildFunc) error {
		err := fake(ctx, c, solveOpt, build)
		assertDirEmpty(t, tmp, "the single-platform export must not use TMPDIR")
		return err
	}
}

// A named export to a new directory is staged beside it and published once
// complete, leaving no staging or temporary directories behind.
func TestNamedOCIExportPublishesAtomically(t *testing.T) {
	for _, platforms := range [][]ispec.Platform{{ociExportAMD64}, {ociExportAMD64, ociExportARM64}} {
		t.Run(fmt.Sprintf("%d platforms", len(platforms)), func(t *testing.T) {
			tmp := isolateTempDir(t)
			solves := stubOCIExporter(t, nil)
			if len(platforms) == 1 {
				stubSinglePlatformTempCheck(t, tmp)
			}
			results, patchPlatforms := namedOCIExportResults(t, platforms)
			parent := t.TempDir()
			output := filepath.Join(parent, "output")
			staged, reason := CanPublishOCILayoutAtomically(output)
			require.True(t, staged, "%v", reason)

			require.NoError(t, CreateOCILayoutFromResultsWithContext(t.Context(), output, results, patchPlatforms, namedOCIExportOptions(true)))
			assert.Len(t, *solves, len(platforms))
			assertNamedOCILayout(t, output, platforms)
			info, err := os.Stat(output)
			require.NoError(t, err)
			assert.Equal(t, newDirMode(t), info.Mode().Perm(), "the layout is published with the usual directory mode")
			assert.Equal(t, []string{"output"}, dirEntryNames(t, parent), "only the published layout remains beside it")
			assertDirEmpty(t, tmp, "temporary platform directories must be removed")
		})
	}
}

// An existing directory is written in place, as before atomic publication was
// added: an empty one receives the layout, and a non-empty one is overwritten.
func TestNamedOCIExportWritesExistingDirectoryInPlace(t *testing.T) {
	for _, platforms := range [][]ispec.Platform{{ociExportAMD64}, {ociExportAMD64, ociExportARM64}} {
		for _, empty := range []bool{true, false} {
			t.Run(fmt.Sprintf("%d platforms/empty=%v", len(platforms), empty), func(t *testing.T) {
				tmp := isolateTempDir(t)
				stubOCIExporter(t, nil)
				if len(platforms) == 1 {
					stubSinglePlatformTempCheck(t, tmp)
				}
				results, patchPlatforms := namedOCIExportResults(t, platforms)
				parent := t.TempDir()
				output := filepath.Join(parent, "output")
				require.NoError(t, os.Mkdir(output, 0o755))
				if !empty {
					require.NoError(t, os.WriteFile(filepath.Join(output, ispec.ImageIndexFile), []byte(`{"earlier":"layout"}`), 0o600))
				}
				staged, _ := CanPublishOCILayoutAtomically(output)
				require.False(t, staged, "an existing directory cannot be published atomically")

				require.NoError(t, CreateOCILayoutFromResultsWithContext(t.Context(), output, results, patchPlatforms, namedOCIExportOptions(false)))
				assertNamedOCILayout(t, output, platforms)
				assert.Equal(t, []string{"output"}, dirEntryNames(t, parent))
				assertDirEmpty(t, tmp, "temporary platform directories must be removed")
			})
		}
	}
}

// interruptingOCIExporter wraps the fake exporter so that the export solve with
// the given index fails, or cancels the export, as a timeout or Ctrl+C would.
// An interrupt index equal to solveCount lets the last solve complete and
// cancels the export before it is unpacked.
func interruptingOCIExporter(t *testing.T, cancel context.CancelFunc, interrupt int, cancelInterrupt bool, solveErr error, solveCount int) *int {
	t.Helper()
	stubOCIExporter(t, nil)
	fake := buildOCIExport
	solves := 0
	buildOCIExport = func(ctx context.Context, c *client.Client, solveOpt client.SolveOpt, build gwclient.BuildFunc) error {
		index := solves
		solves++
		if index == interrupt {
			if !cancelInterrupt {
				return solveErr
			}
			cancel()
		}
		// BuildKit stops a solve whose context is canceled.
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fake(ctx, c, solveOpt, build); err != nil {
			return err
		}
		if last := index == solveCount-1; last && interrupt == solveCount {
			cancel()
		}
		return nil
	}
	return &solves
}

// A named export that fails or is canceled partway must not leave a partial
// layout: an atomic export leaves nothing at or beside the destination, an
// in-place export removes a directory it created and leaves no layout
// metadata in an existing one, and neither leaves temporary directories.
func TestNamedOCIExportInterruptedLeavesNoLayout(t *testing.T) {
	solveErr := errors.New("solve failed")
	for _, mode := range []string{"atomic", "in place, new directory", "in place, existing directory"} {
		for _, tc := range []struct {
			name      string
			platforms []ispec.Platform
			interrupt int
			cancel    bool
		}{
			{name: "canceled after the first of two platforms", platforms: []ispec.Platform{ociExportAMD64, ociExportARM64}, interrupt: 1, cancel: true},
			{name: "canceled after the only platform's solve", platforms: []ispec.Platform{ociExportAMD64}, interrupt: 1, cancel: true},
			{name: "canceled during the first solve", platforms: []ispec.Platform{ociExportAMD64, ociExportARM64}, interrupt: 0, cancel: true},
			{name: "second platform's solve fails", platforms: []ispec.Platform{ociExportAMD64, ociExportARM64}, interrupt: 1},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				tmp := isolateTempDir(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				solves := interruptingOCIExporter(t, cancel, tc.interrupt, tc.cancel, solveErr, len(tc.platforms))
				results, patchPlatforms := namedOCIExportResults(t, tc.platforms)
				parent := t.TempDir()
				output := filepath.Join(parent, "output")
				if mode == "in place, existing directory" {
					require.NoError(t, os.Mkdir(output, 0o755))
				}

				err := CreateOCILayoutFromResultsWithContext(ctx, output, results, patchPlatforms, namedOCIExportOptions(mode == "atomic"))
				if tc.cancel {
					require.ErrorIs(t, err, context.Canceled)
				} else {
					require.ErrorIs(t, err, solveErr)
				}
				assert.Positive(t, *solves)
				if mode == "in place, existing directory" {
					// The patched-only export empties an existing directory
					// before writing to it, as it always has.
					assert.Equal(t, []string{"output"}, dirEntryNames(t, parent))
					assertDirEmpty(t, output, "no partial layout may remain in the existing directory")
				} else {
					assertDirEmpty(t, parent, "no partial layout or staging directory may remain beside the destination")
				}
				assertDirEmpty(t, tmp, "temporary platform directories must be removed")
			})
		}
	}
}

// An in-place export into an existing directory removes what it added if it
// fails, and keeps the user's files, including blobs that were already there.
func TestInPlaceOCILayoutFailureKeepsExistingFiles(t *testing.T) {
	output := t.TempDir()
	userFiles := map[string]string{
		"notes.txt":         "user file",
		"blobs/sha256/aaaa": "existing blob",
	}
	for name, content := range userFiles {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(output, name)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(output, name), []byte(content), 0o600))
	}
	writeErr := errors.New("export failed")
	err := writeOCILayoutInPlace(output, func(dir string) error {
		for _, name := range []string{"blobs/sha256/bbbb", "blobs/sha512/cccc", ispec.ImageLayoutFile, ispec.ImageIndexFile} {
			require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("written by the export"), 0o600))
		}
		return writeErr
	})
	require.ErrorIs(t, err, writeErr)
	for name, content := range userFiles {
		assert.Equal(t, content, string(mustReadFile(t, filepath.Join(output, name))))
	}
	assert.NoFileExists(t, filepath.Join(output, ispec.ImageIndexFile))
	assert.NoFileExists(t, filepath.Join(output, ispec.ImageLayoutFile))
	assert.Equal(t, []string{"aaaa"}, dirEntryNames(t, filepath.Join(output, "blobs", "sha256")))
	assert.NoDirExists(t, filepath.Join(output, "blobs", "sha512"))

	// A layout that was already there is left as it was: the export writes
	// its metadata last, so a failure never reaches it.
	require.NoError(t, os.WriteFile(filepath.Join(output, ispec.ImageIndexFile), []byte("earlier index"), 0o600))
	err = writeOCILayoutInPlace(output, func(dir string) error {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "blobs", "sha256", "dddd"), nil, 0o600))
		return writeErr
	})
	require.ErrorIs(t, err, writeErr)
	assert.Equal(t, "earlier index", string(mustReadFile(t, filepath.Join(output, ispec.ImageIndexFile))))
	assert.NoFileExists(t, filepath.Join(output, "blobs", "sha256", "dddd"))

	// A directory the export created is removed entirely.
	created := filepath.Join(t.TempDir(), "output")
	err = writeOCILayoutInPlace(created, func(dir string) error {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "blobs"), 0o755))
		return writeErr
	})
	require.ErrorIs(t, err, writeErr)
	assert.NoDirExists(t, created)
}

// A mixed export of patched and preserved platforms writes into an existing
// directory without emptying it first, so a canceled export there keeps the
// user's files.
func TestInPlaceMixedOCIExportCanceledKeepsExistingFiles(t *testing.T) {
	tmp := isolateTempDir(t)
	source, descriptors, configs := newMultiPlatformOCIInputTestSource(t, ociExportAMD64, ociExportARM64)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	interruptingOCIExporter(t, cancel, 1, true, nil, 1)
	desc := descriptors[PlatformKey(ociExportAMD64)]
	state := llb.Scratch()
	output := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(output, "notes.txt"), []byte("user file"), 0o600))

	err := CreateOCILayoutFromResultsWithContext(ctx, output,
		[]types.PatchResult{{OCISource: source, PatchedDesc: &desc, PatchedState: &state, ConfigData: configs[PlatformKey(ociExportAMD64)]}},
		[]types.PatchPlatform{{Platform: ociExportAMD64}, {Platform: ociExportARM64, ShouldPreserve: true}},
		OCILayoutExportOptions{OutputReference: "registry.invalid/output:patched", BuildkitOpts: &Opts{Addr: "tcp://127.0.0.1:1"}})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, []string{"notes.txt"}, dirEntryNames(t, output))
	assertDirEmpty(t, tmp, "temporary platform directories must be removed")
}
