package ocilayout_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/util/progress/progressui"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types"
)

const (
	linuxOS   = "linux"
	amd64Arch = "amd64"
	// Alpine 3.21.0; immutable multi-platform input, not a moving latest tag.
	alpineIndex = "index.docker.io/library/alpine@sha256:21dc6063fd678b478f57c0e13f47560d0ea4eeba26dfc947b2a4f81f686b9f45"
	logicalName = "registry.invalid/copa-1677/input:original"
	outputName  = "registry.invalid/copa-1677/output:patched"
)

// Run against an isolated BuildKit endpoint with no host layout mounts:
// COPA_OCI_TEST_ADDR=tcp://127.0.0.1:51677 go test ./integration/ocilayout -v
// The worker must also advertise linux(fixture.1+a+b)/amd64 for the metadata
// scenario, alongside native linux/amd64 and linux/386.
// The caller owns the daemon/resource lane. Source image fallback through a
// Docker daemon is disabled; registry.invalid cannot supply the logical source.
func TestOCILayoutRoundTrip(t *testing.T) {
	addr := os.Getenv("COPA_OCI_TEST_ADDR")
	if addr == "" {
		t.Skip("set COPA_OCI_TEST_ADDR to an isolated BuildKit endpoint")
	}
	t.Setenv("DOCKER_HOST", "unix:///copa-test-no-image-daemon.sock")
	ref, err := name.ParseReference(alpineIndex)
	require.NoError(t, err)
	index, err := remote.Index(ref, remote.WithContext(t.Context()))
	require.NoError(t, err)
	manifest, err := index.IndexManifest()
	require.NoError(t, err)
	images := make(map[string]v1.Image)
	for _, desc := range manifest.Manifests {
		if desc.Platform == nil || desc.Platform.OS != linuxOS || (desc.Platform.Architecture != amd64Arch && desc.Platform.Architecture != "386") {
			continue
		}
		img, err := index.Image(desc.Digest)
		require.NoError(t, err)
		annotated, ok := mutate.Annotations(img, map[string]string{"example.scope": "body"}).(v1.Image)
		require.True(t, ok)
		images[desc.Platform.Architecture] = annotated
	}
	require.Len(t, images, 2)

	options := func(input, output string) *types.Options {
		return &types.Options{
			InputOCILayout: input, OCIDir: output, PatchedTag: outputName,
			BkAddr: addr, Timeout: 4 * time.Minute, PkgTypes: "os", Scanner: "trivy",
			LibraryPatchLevel: "patch", Format: "openvex", Progress: progressui.PlainMode,
		}
	}

	t.Run("unnamed single manifest and final VEX identity", func(t *testing.T) {
		input := writeLayout(t, images, false, false)
		// The first alias has no platform declaration; another supplies an
		// equivalent architecture spelling that must be checked against config.
		indexPath := filepath.Join(input, "index.json")
		indexData, err := os.ReadFile(indexPath)
		require.NoError(t, err)
		var aliases ocispec.Index
		require.NoError(t, json.Unmarshal(indexData, &aliases))
		alias := aliases.Manifests[0]
		alias.Platform = &ocispec.Platform{OS: linuxOS, Architecture: "x86_64"}
		aliases.Manifests = append(aliases.Manifests, alias)
		indexData, err = json.Marshal(aliases)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(indexPath, indexData, 0o600))
		addBodyArtifactAliases(t, input)
		before := snapshot(t, input)
		output := filepath.Join(t.TempDir(), "output")
		opts := options(input, output)
		opts.Report = writeReport(t, amd64Arch)
		opts.Platforms = []string{"linux/amd64", "linux/x86_64", "linux/amd64"}
		opts.Output = filepath.Join(t.TempDir(), "vex.json")
		require.NoError(t, patch.Patch(t.Context(), opts))
		assert.Equal(t, before, snapshot(t, input))
		source := openLayout(t, output)
		platform := &ocispec.Platform{OS: linuxOS, Architecture: amd64Arch}
		desc, err := source.PlatformDescriptor(t.Context(), platform)
		require.NoError(t, err)
		body := readManifest(t, output, desc)
		assert.Equal(t, "body", body.Annotations["example.scope"])
		assert.Equal(t, "descriptor", desc.Annotations["example.scope"])
		assert.Equal(t, "root", source.Descriptor.Annotations["example.root"])
		var config ocispec.Image
		readJSONBlob(t, output, &body.Config, &config)
		assert.NotContains(t, config.Config.Labels, "BaseImage", "an output name must not become the missing source name")
		vexData, err := os.ReadFile(opts.Output)
		require.NoError(t, err)
		assert.Contains(t, string(vexData), desc.Digest.String())
		require.Contains(t, string(vexData), "pkg:oci/output@"+desc.Digest.String())
		assert.NotContains(t, string(vexData), "registry.invalid/copa-1677/input")
		t.Logf("final manifest %s; top-level index %s; VEX verified", desc.Digest, source.Descriptor.Digest)
		// The exported graph must transfer through another OCI-backed solve.
		repatch := options(output, filepath.Join(t.TempDir(), "repatched"))
		require.NoError(t, patch.Patch(t.Context(), repatch))
		openLayout(t, repatch.OCIDir)
	})

	t.Run("full platform metadata survives export", func(t *testing.T) {
		config, err := images[amd64Arch].ConfigFile()
		require.NoError(t, err)
		config.OSVersion = "fixture.1"
		config.OSFeatures = []string{"b", "a"}
		img, err := mutate.ConfigFile(images[amd64Arch], config)
		require.NoError(t, err)
		input := writeLayout(t, map[string]v1.Image{amd64Arch: img}, false, false)
		before := snapshot(t, input)
		opts := options(input, filepath.Join(t.TempDir(), "output"))
		require.NoError(t, patch.Patch(t.Context(), opts))
		assert.Equal(t, before, snapshot(t, input))
		found, err := openLayout(t, opts.OCIDir).Platforms(t.Context())
		require.NoError(t, err)
		require.Len(t, found, 1)
		assert.Equal(t, "fixture.1", found[0].OSVersion)
		assert.Equal(t, []string{"a", "b"}, found[0].OSFeatures)
		desc, err := openLayout(t, opts.OCIDir).PlatformDescriptor(t.Context(), &found[0])
		require.NoError(t, err)
		assert.Equal(t, found[0], *desc.Platform)
	})

	t.Run("formerly colliding platform results export independently", func(t *testing.T) {
		identities := []ocispec.Platform{
			{OS: linuxOS, Architecture: amd64Arch, OSVersion: `1+["x"]`},
			{OS: linuxOS, Architecture: amd64Arch, OSVersion: "1", OSFeatures: []string{"x"}},
		}
		variants := make(map[string]v1.Image)
		for i, identity := range identities {
			config, err := images[amd64Arch].ConfigFile()
			require.NoError(t, err)
			config.OSVersion, config.OSFeatures = identity.OSVersion, identity.OSFeatures
			config.Config.Labels = map[string]string{"example.identity": fmt.Sprint(i)}
			img, err := mutate.ConfigFile(images[amd64Arch], config)
			require.NoError(t, err)
			variants[fmt.Sprint(i)] = img
		}
		input := writeLayout(t, variants, true, false)
		before := snapshot(t, input)
		source := openLayout(t, input)
		var results []types.PatchResult
		var targets []types.PatchPlatform
		for i, identity := range identities {
			config, err := variants[fmt.Sprint(i)].RawConfigFile()
			require.NoError(t, err)
			state, err := source.State(t.Context(), &identity, config)
			require.NoError(t, err)
			desc, err := source.PlatformDescriptor(t.Context(), &identity)
			require.NoError(t, err)
			results = append(results, types.PatchResult{OCISource: source, PatchedDesc: desc, PatchedState: &state, ConfigData: config})
			targets = append(targets, types.PatchPlatform{Platform: identity})
		}
		output := filepath.Join(t.TempDir(), "output")
		require.NoError(t, buildkit.CreateOCILayoutFromResultsWithOptions(output, results, targets,
			buildkit.OCILayoutExportOptions{OutputReference: outputName, Atomic: true, BuildkitOpts: &buildkit.Opts{Addr: addr}}.WithContext(t.Context())))
		assert.Equal(t, before, snapshot(t, input))
		exported := openLayout(t, output)
		found, err := exported.Platforms(t.Context())
		require.NoError(t, err)
		require.Len(t, found, 2)
		for i, identity := range identities {
			desc, err := exported.PlatformDescriptor(t.Context(), &identity)
			require.NoError(t, err)
			manifest := readManifest(t, output, desc)
			var config ocispec.Image
			readJSONBlob(t, output, &manifest.Config, &config)
			assert.Equal(t, identity, config.Platform)
			assert.Equal(t, fmt.Sprint(i), config.Config.Labels["example.identity"])
		}
	})

	t.Run("selected platform preserves exact sibling content", func(t *testing.T) {
		input := writeLayout(t, images, true, true)
		addBodyArtifactAliases(t, input)
		before := snapshot(t, input)
		opts := options(input, filepath.Join(t.TempDir(), "output"))
		opts.Image = logicalName
		opts.Platforms = []string{"linux/amd64", "linux/x86_64", "linux/amd64"}
		require.NoError(t, patch.Patch(t.Context(), opts))
		assert.Equal(t, before, snapshot(t, input))
		assertPreserved(t, input, opts.OCIDir, "386")
		output := openLayout(t, opts.OCIDir)
		annotations, err := output.IndexAnnotations(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "index", annotations["example.index"])
		assert.Contains(t, annotations, "sh.copa.patched")
	})

	t.Run("single report deduplicates selectors and preserves sibling", func(t *testing.T) {
		input := writeLayout(t, images, true, false)
		before := snapshot(t, input)
		workRoot := t.TempDir()
		require.NoError(t, os.Chmod(workRoot, 0o744))
		opts := options(input, filepath.Join(workRoot, "output"))
		opts.WorkingFolder = workRoot
		opts.Report = writeReport(t, amd64Arch)
		opts.Platforms = []string{"linux/amd64", "linux/x86_64", "linux/amd64"}
		require.NoError(t, patch.Patch(t.Context(), opts))
		assert.Equal(t, before, snapshot(t, input))
		assertPreserved(t, input, opts.OCIDir, "386")
		found, err := openLayout(t, opts.OCIDir).Platforms(t.Context())
		require.NoError(t, err)
		require.Len(t, found, 2)
	})

	t.Run("report directory preserves platform without report", func(t *testing.T) {
		input := writeLayout(t, images, true, false)
		opts := options(input, filepath.Join(t.TempDir(), "output"))
		opts.Report = filepath.Dir(writeReport(t, amd64Arch))
		opts.Output = filepath.Join(t.TempDir(), "vex.json")
		require.NoError(t, patch.Patch(t.Context(), opts))
		assertPreserved(t, input, opts.OCIDir, "386")
	})

	t.Run("all platforms with digest selector", func(t *testing.T) {
		input := writeLayout(t, images, true, false)
		before := snapshot(t, input)
		opts := options(input, filepath.Join(t.TempDir(), "output"))
		opts.Image = openLayout(t, input).Descriptor.Digest.String()
		require.NoError(t, patch.Patch(t.Context(), opts))
		assert.Equal(t, before, snapshot(t, input))
		output := openLayout(t, opts.OCIDir)
		found, err := output.Platforms(t.Context())
		require.NoError(t, err)
		require.Len(t, found, 2)
		for _, platform := range found {
			beforeDesc, err := openLayout(t, input).PlatformDescriptor(t.Context(), &platform)
			require.NoError(t, err)
			afterDesc, err := output.PlatformDescriptor(t.Context(), &platform)
			require.NoError(t, err)
			assert.NotEqual(t, beforeDesc.Digest, afterDesc.Digest)
		}
	})

	t.Run("reportless output does not produce VEX", func(t *testing.T) {
		for _, multi := range []bool{false, true} {
			input := writeLayout(t, images, multi, false)
			before := snapshot(t, input)
			opts := options(input, filepath.Join(t.TempDir(), "output"))
			opts.Output = filepath.Join(t.TempDir(), "vex.json")
			opts.Format = "unsupported-vex-format"
			require.NoError(t, patch.Patch(t.Context(), opts))
			openLayout(t, opts.OCIDir)
			assert.Equal(t, before, snapshot(t, input))
			_, err := os.Stat(opts.Output)
			assert.True(t, os.IsNotExist(err), "reportless patch must not emit VEX")
		}
	})

	t.Run("unsupported source platforms are preserved", func(t *testing.T) {
		unsupported := make(map[string]v1.Image)
		for _, platform := range []ocispec.Platform{
			{OS: "windows", Architecture: amd64Arch, OSVersion: "10.0.20348.0"},
			{OS: linuxOS, Architecture: "mips64le"},
		} {
			config, err := images[amd64Arch].ConfigFile()
			require.NoError(t, err)
			config.OS, config.Architecture, config.OSVersion = platform.OS, platform.Architecture, platform.OSVersion
			img, err := mutate.ConfigFile(images[amd64Arch], config)
			require.NoError(t, err)
			unsupported[platform.OS+"/"+platform.Architecture] = img
		}
		mixed := map[string]v1.Image{amd64Arch: images[amd64Arch]}
		for key, image := range unsupported {
			mixed[key] = image
		}
		input := writeLayout(t, mixed, true, false)
		before := snapshot(t, input)
		for _, mode := range []string{"reportless", "report file", "report directory"} {
			t.Run(mode, func(t *testing.T) {
				opts := options(input, filepath.Join(t.TempDir(), "output"))
				if mode != "reportless" {
					opts.Report = writeReport(t, amd64Arch)
					if mode == "report directory" {
						opts.Report = filepath.Dir(opts.Report)
					}
				}
				require.NoError(t, patch.Patch(t.Context(), opts))
				assert.Equal(t, before, snapshot(t, input))
				found, err := openLayout(t, input).Platforms(t.Context())
				require.NoError(t, err)
				for _, platform := range found {
					if platform.OS != linuxOS || platform.Architecture != amd64Arch {
						assertPlatformPreserved(t, input, opts.OCIDir, &platform)
					}
				}
			})
		}
		t.Run("report directory rejects unsupported sibling report", func(t *testing.T) {
			opts := options(input, filepath.Join(t.TempDir(), "output"))
			opts.Report = filepath.Dir(writeReport(t, amd64Arch))
			data, err := os.ReadFile(writeReport(t, "mips64le"))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(opts.Report, "unsupported.json"), data, 0o600))
			assert.ErrorContains(t, patch.Patch(t.Context(), opts), "unsupported scan report")
			assert.Equal(t, before, snapshot(t, input))
			_, err = os.Stat(opts.OCIDir)
			assert.True(t, os.IsNotExist(err), "unsupported report must prevent publication")
		})
		for _, target := range []string{"windows/amd64", "linux/mips64le"} {
			opts := options(input, filepath.Join(t.TempDir(), "output"))
			opts.Platforms = []string{target}
			require.ErrorContains(t, patch.Patch(t.Context(), opts), "unsupported platform")
			_, err := os.Stat(opts.OCIDir)
			assert.True(t, os.IsNotExist(err))
		}
		input = writeLayout(t, unsupported, true, false)
		before = snapshot(t, input)
		opts := options(input, filepath.Join(t.TempDir(), "output"))
		opts.BkAddr = "tcp://127.0.0.1:1" // Rejection must precede any BuildKit connection.
		require.ErrorContains(t, patch.Patch(t.Context(), opts), "no supported patch platforms")
		assert.Equal(t, before, snapshot(t, input))
		_, err := os.Stat(opts.OCIDir)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("ignored OCI failure preserves source without a VEX claim", func(t *testing.T) {
		broken, err := mutate.AppendLayers(images["386"], static.NewLayer([]byte("not a tar archive"), v1types.OCIUncompressedLayer))
		require.NoError(t, err)
		input := writeLayout(t, map[string]v1.Image{amd64Arch: images[amd64Arch], "386": broken}, true, false)
		before := snapshot(t, input)
		reportDir := t.TempDir()
		for _, arch := range []string{amd64Arch, "386"} {
			require.NoError(t, os.Rename(writeReport(t, arch), filepath.Join(reportDir, arch+".json")))
		}
		for _, ignore := range []bool{false, true} {
			opts := options(input, filepath.Join(t.TempDir(), "output"))
			opts.Report, opts.IgnoreError = reportDir, ignore
			opts.Output = filepath.Join(t.TempDir(), "vex.json")
			err := patch.Patch(t.Context(), opts)
			assert.Equal(t, before, snapshot(t, input))
			if !ignore {
				require.ErrorContains(t, err, "one or more platform patches failed")
				_, err = os.Stat(opts.OCIDir)
				assert.True(t, os.IsNotExist(err))
				continue
			}
			require.NoError(t, err)
			assertPreserved(t, input, opts.OCIDir, "386")
			output := openLayout(t, opts.OCIDir)
			patched, err := output.PlatformDescriptor(t.Context(), &ocispec.Platform{OS: linuxOS, Architecture: amd64Arch})
			require.NoError(t, err)
			preserved, err := output.PlatformDescriptor(t.Context(), &ocispec.Platform{OS: linuxOS, Architecture: "386"})
			require.NoError(t, err)
			data, err := os.ReadFile(opts.Output)
			require.NoError(t, err)
			assert.Contains(t, string(data), patched.Digest.String())
			assert.NotContains(t, string(data), preserved.Digest.String())
		}
		brokenAMD64, err := mutate.AppendLayers(images[amd64Arch], static.NewLayer([]byte("not a tar archive"), v1types.OCIUncompressedLayer))
		require.NoError(t, err)
		input = writeLayout(t, map[string]v1.Image{amd64Arch: brokenAMD64, "386": broken}, true, false)
		before = snapshot(t, input)
		opts := options(input, filepath.Join(t.TempDir(), "output"))
		opts.IgnoreError = true
		require.ErrorContains(t, patch.Patch(t.Context(), opts), "all platform patches failed")
		assert.Equal(t, before, snapshot(t, input))
		_, err = os.Stat(opts.OCIDir)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("sole source rejects mismatched explicit and report targets", func(t *testing.T) {
		input := writeLayout(t, images, false, false)
		before := snapshot(t, input)
		for _, withReport := range []bool{false, true} {
			opts := options(input, filepath.Join(t.TempDir(), "output"))
			if withReport {
				opts.Report = writeReport(t, "arm64")
			} else {
				opts.Platforms = []string{"linux/arm64"}
			}
			require.ErrorContains(t, patch.Patch(t.Context(), opts), "matches 0 platforms")
			assert.Equal(t, before, snapshot(t, input))
			_, err := os.Stat(opts.OCIDir)
			assert.True(t, os.IsNotExist(err))
		}
	})

	t.Run("working folder inside output fails before patching", func(t *testing.T) {
		input := writeLayout(t, images, false, false)
		before := snapshot(t, input)
		opts := options(input, filepath.Join(t.TempDir(), "output"))
		opts.WorkingFolder = filepath.Join(opts.OCIDir, "work")
		opts.Report = writeReport(t, amd64Arch)
		require.ErrorContains(t, patch.Patch(t.Context(), opts), "must not be inside OCI layout output")
		assert.Equal(t, before, snapshot(t, input))
		_, err := os.Stat(opts.OCIDir)
		assert.True(t, os.IsNotExist(err), "rejection must precede working-folder creation")
	})

	t.Run("failed source unpack leaves input and output untouched", func(t *testing.T) {
		broken, err := mutate.AppendLayers(images[amd64Arch], static.NewLayer([]byte("not a tar archive"), v1types.OCIUncompressedLayer))
		require.NoError(t, err)
		input := writeLayout(t, map[string]v1.Image{amd64Arch: broken}, false, false)
		before := snapshot(t, input)
		opts := options(input, filepath.Join(t.TempDir(), "output"))
		require.ErrorContains(t, patch.Patch(t.Context(), opts), "unexpected EOF")
		assert.Equal(t, before, snapshot(t, input))
		_, err = os.Stat(opts.OCIDir)
		assert.True(t, os.IsNotExist(err), "failed operation must not publish a partial output")
	})
}

func writeLayout(t *testing.T, images map[string]v1.Image, multi, named bool) string {
	t.Helper()
	root := t.TempDir()
	out, err := layout.Write(root, empty.Index)
	require.NoError(t, err)
	annotations := map[string]string{"example.root": "root", "example.scope": "descriptor"}
	if named {
		annotations["io.containerd.image.name"] = logicalName
	}
	if !multi {
		require.NoError(t, out.AppendImage(images[amd64Arch], layout.WithAnnotations(annotations)))
		return root
	}
	var adds []mutate.IndexAddendum
	keys := make([]string, 0, len(images))
	for key := range images {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		config, err := images[key].ConfigFile()
		require.NoError(t, err)
		adds = append(adds, mutate.IndexAddendum{Add: images[key], Descriptor: v1.Descriptor{
			Platform:    &v1.Platform{OS: config.OS, Architecture: config.Architecture, Variant: config.Variant, OSVersion: config.OSVersion, OSFeatures: config.OSFeatures},
			Annotations: map[string]string{"example.scope": "descriptor"},
		}})
	}
	index := mutate.AppendManifests(empty.Index, adds...)
	index, ok := mutate.Annotations(index, map[string]string{"example.index": "index"}).(v1.ImageIndex)
	require.True(t, ok)
	require.NoError(t, out.AppendIndex(index, layout.WithAnnotations(annotations)))
	return root
}

func openLayout(t *testing.T, path string) *ocilayout.Source {
	t.Helper()
	source, err := ocilayout.Open(t.Context(), path, "", "")
	require.NoError(t, err)
	return source
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	require.NoError(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[rel] = digest.FromBytes(data).String()
		return nil
	}))
	return result
}

func readJSONBlob(t *testing.T, root string, desc *ocispec.Descriptor, target any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "blobs", desc.Digest.Algorithm().String(), desc.Digest.Encoded()))
	require.NoError(t, err)
	require.Equal(t, desc.Digest, digest.FromBytes(data))
	require.NoError(t, json.Unmarshal(data, target))
}

func readManifest(t *testing.T, root string, desc *ocispec.Descriptor) ocispec.Manifest {
	t.Helper()
	var manifest ocispec.Manifest
	readJSONBlob(t, root, desc, &manifest)
	return manifest
}

func assertPreserved(t *testing.T, input, output, arch string) {
	t.Helper()
	assertPlatformPreserved(t, input, output, &ocispec.Platform{OS: linuxOS, Architecture: arch})
}

func assertPlatformPreserved(t *testing.T, input, output string, platform *ocispec.Platform) {
	t.Helper()
	before, err := openLayout(t, input).PlatformDescriptor(t.Context(), platform)
	require.NoError(t, err)
	after, err := openLayout(t, output).PlatformDescriptor(t.Context(), platform)
	require.NoError(t, err)
	require.Equal(t, *before, *after)
	manifest := readManifest(t, input, before)
	for _, desc := range append([]ocispec.Descriptor{*before, manifest.Config}, manifest.Layers...) {
		rel := filepath.Join("blobs", desc.Digest.Algorithm().String(), desc.Digest.Encoded())
		left, err := os.ReadFile(filepath.Join(input, rel))
		require.NoError(t, err)
		right, err := os.ReadFile(filepath.Join(output, rel))
		require.NoError(t, err)
		assert.Equal(t, left, right, desc.Digest.String())
	}
}

func writeReport(t *testing.T, arch string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	data := fmt.Sprintf(`{
  "SchemaVersion":2,"ArtifactName":"%s","ArtifactType":"container_image",
  "Metadata":{"OS":{"Family":"alpine","Name":"3.21.0"},"ImageConfig":{"architecture":"%s"}},
  "Results":[{"Target":"alpine (alpine 3.21.0)","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[{
    "VulnerabilityID":"CVE-2025-46394","PkgName":"busybox","InstalledVersion":"1.37.0-r8","FixedVersion":"1.37.0-r9"
  }]}]
}`, logicalName, arch)
	require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
	return path
}

// Ordinary producer output may repeat config mediaType in descriptor artifactType.
func TestOCILayoutFixtures(t *testing.T) {
	for _, configType := range []v1types.MediaType{v1types.OCIConfigJSON, v1types.DockerConfigJSON} {
		t.Run(string(configType), func(t *testing.T) {
			images := make(map[string]v1.Image)
			for _, arch := range []string{amd64Arch, "386"} {
				config, err := empty.Image.ConfigFile()
				require.NoError(t, err)
				config.OS, config.Architecture = linuxOS, arch
				img, err := mutate.ConfigFile(empty.Image, config)
				require.NoError(t, err)
				images[arch] = mutate.ConfigMediaType(img, configType)
			}
			for _, multi := range []bool{false, true} {
				source := openLayout(t, writeLayout(t, images, multi, false))
				platforms, err := source.Platforms(t.Context())
				require.NoError(t, err)
				if multi {
					require.Len(t, platforms, 2)
				} else {
					require.Len(t, platforms, 1)
				}
				for _, platform := range platforms {
					desc, err := source.PlatformDescriptor(t.Context(), &platform)
					require.NoError(t, err)
					require.Equal(t, string(configType), desc.ArtifactType)
				}
			}
		})
	}
}

func TestOCILayoutRejectsOverlappingTempDir(t *testing.T) {
	config, err := empty.Image.ConfigFile()
	require.NoError(t, err)
	config.OS, config.Architecture = linuxOS, amd64Arch
	img, err := mutate.ConfigFile(empty.Image, config)
	require.NoError(t, err)
	input := writeLayout(t, map[string]v1.Image{amd64Arch: img}, false, false)
	nested := filepath.Join(input, "tmp")
	require.NoError(t, os.Mkdir(nested, 0o755))
	link := filepath.Join(t.TempDir(), "source-link")
	require.NoError(t, os.Symlink(input, link))
	for _, tempRoot := range []string{input, nested, link} {
		t.Run(filepath.Base(tempRoot), func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output")
			working := t.TempDir()
			before := snapshot(t, input)
			t.Setenv("TMPDIR", tempRoot)
			for _, work := range []string{"", working} {
				err := patch.Patch(t.Context(), &types.Options{
					InputOCILayout: input, OCIDir: output, PatchedTag: outputName,
					WorkingFolder: work, BkAddr: "tcp://127.0.0.1:1", Timeout: time.Second,
					PkgTypes: "os", Progress: progressui.QuietMode,
				})
				require.ErrorContains(t, err, "temporary directory")
				assert.Equal(t, before, snapshot(t, input))
				_, err = os.Stat(output)
				assert.True(t, os.IsNotExist(err))
			}
		})
	}
}

func addBodyArtifactAliases(t *testing.T, root string) {
	t.Helper()
	indexPath := filepath.Join(root, ocispec.ImageIndexFile)
	data, err := os.ReadFile(indexPath)
	require.NoError(t, err)
	var index ocispec.Index
	require.NoError(t, json.Unmarshal(data, &index))
	for _, mediaType := range []string{ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex} {
		data, err := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mediaType, "artifactType": "application/example"})
		require.NoError(t, err)
		dgst := digest.FromBytes(data)
		require.NoError(t, os.WriteFile(filepath.Join(root, "blobs", dgst.Algorithm().String(), dgst.Encoded()), data, 0o600))
		index.Manifests = append(index.Manifests, ocispec.Descriptor{
			MediaType: mediaType, Digest: dgst, Size: int64(len(data)),
			Annotations: map[string]string{"io.containerd.image.name": logicalName, ocispec.AnnotationRefName: "original"},
		})
	}
	data, err = json.Marshal(index)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(indexPath, data, 0o600))
}

func TestOCILayoutRejectsUnsupportedSingleReport(t *testing.T) {
	images := make(map[string]v1.Image)
	for _, arch := range []string{amd64Arch, "mips64le"} {
		config, err := empty.Image.ConfigFile()
		require.NoError(t, err)
		config.OS, config.Architecture = linuxOS, arch
		img, err := mutate.ConfigFile(empty.Image, config)
		require.NoError(t, err)
		images[arch] = img
	}
	input := writeLayout(t, images, true, false)
	before := snapshot(t, input)
	for _, ignore := range []bool{false, true} {
		opts := &types.Options{
			InputOCILayout: input, OCIDir: filepath.Join(t.TempDir(), "output"), PatchedTag: outputName,
			Report: writeReport(t, "mips64le"), Scanner: "trivy", PkgTypes: "os", LibraryPatchLevel: "patch",
			BkAddr: "tcp://127.0.0.1:1", Timeout: time.Second, IgnoreError: ignore, Progress: progressui.QuietMode,
		}
		require.ErrorContains(t, patch.Patch(t.Context(), opts), "unsupported scan report platform")
		assert.Equal(t, before, snapshot(t, input))
		_, err := os.Stat(opts.OCIDir)
		assert.True(t, os.IsNotExist(err))
	}
}

func TestOCILayoutSingleReportRejectsDistinctTargetsAndConflicts(t *testing.T) {
	images := make(map[string]v1.Image)
	for _, arch := range []string{amd64Arch, "386"} {
		config, err := empty.Image.ConfigFile()
		require.NoError(t, err)
		config.OS, config.Architecture = linuxOS, arch
		img, err := mutate.ConfigFile(empty.Image, config)
		require.NoError(t, err)
		images[arch] = img
	}
	input := writeLayout(t, images, true, false)
	before := snapshot(t, input)
	for _, test := range []struct {
		name       string
		targets    []string
		reportArch string
		wantError  string
	}{
		{"distinct targets", []string{"linux/amd64", "linux/386"}, amd64Arch, "only one platform"},
		{"conflicting report", []string{"linux/amd64", "linux/x86_64"}, "386", "report platform conflicts"},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts := &types.Options{
				InputOCILayout: input, OCIDir: filepath.Join(t.TempDir(), "output"), PatchedTag: outputName,
				Report: writeReport(t, test.reportArch), Platforms: test.targets, Scanner: "trivy", PkgTypes: "os", LibraryPatchLevel: "patch",
				BkAddr: "tcp://127.0.0.1:1", Timeout: time.Second, Progress: progressui.QuietMode,
			}
			require.ErrorContains(t, patch.Patch(t.Context(), opts), test.wantError)
			assert.Equal(t, before, snapshot(t, input))
			_, err := os.Stat(opts.OCIDir)
			assert.True(t, os.IsNotExist(err))
		})
	}
}

func TestOCILayoutRejectsUnsupportedDirectoryReports(t *testing.T) {
	for _, platform := range []ocispec.Platform{{OS: linuxOS, Architecture: "mips64le"}, {OS: "windows", Architecture: amd64Arch}} {
		t.Run(platform.OS+"/"+platform.Architecture, func(t *testing.T) {
			images := make(map[string]v1.Image)
			for _, identity := range []ocispec.Platform{{OS: linuxOS, Architecture: amd64Arch}, platform} {
				config, err := empty.Image.ConfigFile()
				require.NoError(t, err)
				config.OS, config.Architecture = identity.OS, identity.Architecture
				img, err := mutate.ConfigFile(empty.Image, config)
				require.NoError(t, err)
				images[identity.OS+"/"+identity.Architecture] = img
			}
			input := writeLayout(t, images, true, false)
			before := snapshot(t, input)
			for _, mixed := range []bool{false, true} {
				for _, ignore := range []bool{false, true} {
					reportFile := writeReport(t, platform.Architecture)
					if platform.OS == "windows" {
						data, err := os.ReadFile(reportFile)
						require.NoError(t, err)
						data = []byte(strings.ReplaceAll(string(data), `"Family":"alpine"`, `"Family":"windows"`))
						require.NoError(t, os.WriteFile(reportFile, data, 0o600))
					}
					if platform.OS == "windows" {
						ordinary, err := buildkit.DiscoverPlatformsFromReport(filepath.Dir(reportFile), "trivy")
						require.NoError(t, err)
						assert.Empty(t, ordinary, "named-image discovery retains its unsupported OS policy")
					}
					if mixed {
						data, err := os.ReadFile(writeReport(t, amd64Arch))
						require.NoError(t, err)
						require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(reportFile), "supported.json"), data, 0o600))
					}
					opts := &types.Options{
						InputOCILayout: input, OCIDir: filepath.Join(t.TempDir(), "output"), PatchedTag: outputName,
						Report: filepath.Dir(reportFile), Scanner: "trivy", PkgTypes: "os", LibraryPatchLevel: "patch",
						BkAddr: "tcp://127.0.0.1:1", Timeout: time.Second, IgnoreError: ignore, Progress: progressui.QuietMode,
					}
					err := patch.Patch(t.Context(), opts)
					assert.ErrorContains(t, err, "unsupported scan report", "mixed=%v ignore=%v", mixed, ignore)
					assert.Equal(t, before, snapshot(t, input))
					_, err = os.Stat(opts.OCIDir)
					assert.True(t, os.IsNotExist(err), "no output for rejected report")
				}
			}
		})
	}
}

func TestOCILayoutRejectsOutputWriteConflicts(t *testing.T) {
	config, err := empty.Image.ConfigFile()
	require.NoError(t, err)
	config.OS, config.Architecture = linuxOS, amd64Arch
	img, err := mutate.ConfigFile(empty.Image, config)
	require.NoError(t, err)
	input := writeLayout(t, map[string]v1.Image{amd64Arch: img}, false, false)
	before := snapshot(t, input)
	for _, kind := range []string{"working folder", "VEX file"} {
		for _, relation := range []string{"equal", "nested", "symlink"} {
			t.Run(kind+"/"+relation, func(t *testing.T) {
				parent := t.TempDir()
				output := filepath.Join(parent, "output")
				writePath := output
				switch relation {
				case "nested":
					writePath = filepath.Join(output, "auxiliary")
				case "symlink":
					link := filepath.Join(t.TempDir(), "output-parent")
					require.NoError(t, os.Symlink(parent, link))
					writePath = filepath.Join(link, "output", "auxiliary")
				}
				opts := &types.Options{
					InputOCILayout: input, OCIDir: output, PatchedTag: outputName,
					Report: writeReport(t, amd64Arch), Scanner: "trivy", PkgTypes: "os", LibraryPatchLevel: "patch",
					BkAddr: "tcp://127.0.0.1:1", Timeout: time.Second, Progress: progressui.QuietMode,
				}
				if kind == "working folder" {
					opts.WorkingFolder = writePath
				} else {
					opts.Output = writePath
				}
				require.ErrorContains(t, patch.Patch(t.Context(), opts), "must not be inside OCI layout output")
				assert.Equal(t, before, snapshot(t, input))
				_, err := os.Stat(output)
				assert.True(t, os.IsNotExist(err))
			})
		}
	}
}
