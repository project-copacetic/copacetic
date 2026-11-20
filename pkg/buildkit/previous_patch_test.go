package buildkit

import (
	"encoding/json"
	"testing"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/mocks"
	"github.com/project-copacetic/copacetic/pkg/types"
)

// testLayer is a layer of a test image config and the comment on its history
// entry, which records what added the layer.
type testLayer struct {
	diffID  digest.Digest
	comment string
}

var (
	testOriginalLayer = testLayer{digest.FromString("original OS layer"), ""}
	// BuildKit's exporter describes each layer a Copa patch adds.
	testPatchLayer   = testLayer{digest.FromString("copa patch layer"), exporterHistoryComment}
	testPatchLayer2  = testLayer{digest.FromString("second copa patch layer"), exporterHistoryComment}
	testDerivedLayer = testLayer{digest.FromString("application layer"), "buildkit.dockerfile.v0"}
)

// withTestLayers returns config with a rootfs of layers and one history entry
// for each layer.
func withTestLayers(t testing.TB, config []byte, layers ...testLayer) []byte {
	t.Helper()
	var image map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(config, &image))
	rootFS := specs.RootFS{Type: "layers", DiffIDs: []digest.Digest{}}
	history := []specs.History{}
	for _, layer := range layers {
		rootFS.DiffIDs = append(rootFS.DiffIDs, layer.diffID)
		history = append(history, specs.History{CreatedBy: "add " + layer.diffID.Encoded()[:12], Comment: layer.comment})
	}
	var err error
	image["rootfs"], err = json.Marshal(rootFS)
	require.NoError(t, err)
	image["history"], err = json.Marshal(history)
	require.NoError(t, err)
	updated, err := json.Marshal(image)
	require.NoError(t, err)
	return updated
}

// originalTestConfig returns config as an unpatched image with one layer.
func originalTestConfig(t testing.TB, config []byte) []byte {
	t.Helper()
	return withTestLayers(t, config, testOriginalLayer)
}

// copaOutputTestConfig returns config as a Copa output of originalTestConfig.
func copaOutputTestConfig(t testing.TB, config []byte) []byte {
	t.Helper()
	return withTestLayers(t, config, testOriginalLayer, testPatchLayer)
}

func TestVerifyPreviousPatchLayers(t *testing.T) {
	base := []byte(`{"os":"linux","architecture":"amd64","config":{}}`)
	emptyLayer := specs.History{CreatedBy: "ENV A=b", Comment: "buildkit.dockerfile.v0", EmptyLayer: true}
	withHistory := func(config []byte, extra ...specs.History) []byte {
		var image specs.Image
		require.NoError(t, json.Unmarshal(config, &image))
		image.History = append(image.History, extra...)
		updated, err := json.Marshal(image)
		require.NoError(t, err)
		return updated
	}

	for _, tc := range []struct {
		name    string
		input   []byte
		base    []byte
		wantErr string
	}{
		{
			name:  "re-patch output adds one patch layer",
			input: withTestLayers(t, base, testOriginalLayer, testPatchLayer),
			base:  originalTestConfig(t, base),
		},
		{
			name:  "first patch output may add several patch layers",
			input: withTestLayers(t, base, testOriginalLayer, testPatchLayer, testPatchLayer2),
			base:  originalTestConfig(t, base),
		},
		{
			name:  "output with no patch layers has the base layers",
			input: originalTestConfig(t, base),
			base:  originalTestConfig(t, base),
		},
		{
			name:  "empty-layer history entries are not layers",
			input: withHistory(copaOutputTestConfig(t, base), emptyLayer),
			base:  originalTestConfig(t, base),
		},
		{
			name:    "image built FROM a Copa output has its own layers",
			input:   withTestLayers(t, base, testOriginalLayer, testPatchLayer, testDerivedLayer),
			base:    originalTestConfig(t, base),
			wantErr: "layer 2 above the base image's layers was not added by a Copa patch",
		},
		{
			name:    "layers added by another builder are not a patch",
			input:   withTestLayers(t, base, testOriginalLayer, testLayer{digest.FromString("docker commit"), ""}),
			base:    originalTestConfig(t, base),
			wantErr: "layer 1 above the base image's layers was not added by a Copa patch",
		},
		{
			name:    "image not built on the base",
			input:   withTestLayers(t, base, testDerivedLayer, testPatchLayer),
			base:    originalTestConfig(t, base),
			wantErr: "do not start with the base image's layers",
		},
		{
			name:    "image with fewer layers than the base",
			input:   originalTestConfig(t, base),
			base:    copaOutputTestConfig(t, base),
			wantErr: "do not start with the base image's layers",
		},
		{
			name:    "history that does not describe each layer",
			input:   withHistory(withTestLayers(t, base, testOriginalLayer, testPatchLayer), specs.History{Comment: exporterHistoryComment}),
			base:    originalTestConfig(t, base),
			wantErr: "history does not describe each of its layers",
		},
		{
			name:    "input without a rootfs",
			input:   base,
			base:    originalTestConfig(t, base),
			wantErr: "cannot be compared",
		},
		{
			name:    "base without a rootfs",
			input:   copaOutputTestConfig(t, base),
			base:    base,
			wantErr: "cannot be compared",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyPreviousPatchLayers(tc.input, tc.base)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// An image built FROM a Copa output inherits its BaseImage and origin labels.
// It is patched as supplied and recorded as its own origin, while a real Copa
// output is still re-patched from its recorded base.
func TestUpdateImageConfigDataPatchesDerivedImageAsSupplied(t *testing.T) {
	const (
		osBase   = "registry.example/os:base"
		app      = "registry.example/app:1.0"
		appLocal = "registry.example/app:local"
	)
	osDigest, appDigest := digest.FromString("os base"), digest.FromString("app 1.0")
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	runtime := []byte(`{"os":"linux","architecture":"amd64","config":{"Labels":{"com.example.app":"kept"}}}`)
	baseConfig := originalTestConfig(t, []byte(`{"os":"linux","architecture":"amd64","config":{}}`))
	osOrigin := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: osBase, Digest: osDigest}).Annotations()
	labels := func(t *testing.T, config []byte, extra map[string]string) []byte {
		t.Helper()
		updated, err := AddImageConfigLabels(config, extra)
		require.NoError(t, err)
		return updated
	}
	legacy := map[string]string{"BaseImage": osBase}
	withOrigin := map[string]string{"BaseImage": osBase}
	for key, value := range osOrigin {
		withOrigin[key] = value
	}

	for _, tc := range []struct {
		name     string
		input    []byte
		repatch  bool
		validate bool
	}{
		{
			name:  "derived from a legacy Copa output",
			input: labels(t, withTestLayers(t, runtime, testOriginalLayer, testPatchLayer, testDerivedLayer), legacy),
		},
		{
			name:  "derived from a Copa output with origin labels",
			input: labels(t, withTestLayers(t, runtime, testOriginalLayer, testPatchLayer, testDerivedLayer), withOrigin),
		},
		{
			name:  "legacy BaseImage that the image was not built on",
			input: labels(t, withTestLayers(t, runtime, testDerivedLayer, testPatchLayer), legacy),
		},
		{
			name:    "legacy Copa output",
			input:   labels(t, copaOutputTestConfig(t, runtime), legacy),
			repatch: true,
		},
		{
			name:     "Copa output with origin labels",
			input:    labels(t, copaOutputTestConfig(t, runtime), withOrigin),
			repatch:  true,
			validate: true,
		},
		{
			name:     "Copa output with several first-patch layers",
			input:    labels(t, withTestLayers(t, runtime, testOriginalLayer, testPatchLayer, testPatchLayer2), withOrigin),
			repatch:  true,
			validate: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &mocks.MockGWClient{}
			client.On("ResolveImageConfig", mock.Anything, osBase, mock.Anything).
				Return(osBase, osDigest, baseConfig, nil).Once()

			config, patched, image, lineage, validated, err := updateImageConfigData(t.Context(), client, tc.input, app, appLocal, appDigest, platform)
			require.NoError(t, err)
			client.AssertExpectations(t)
			got := configLabels(t, config)
			assert.Equal(t, tc.validate, validated)
			if tc.repatch {
				assert.Equal(t, osBase, image, "a Copa output is re-patched from its recorded base")
				assert.Equal(t, tc.input, patched)
				assert.Equal(t, osBase, got["BaseImage"])
				if tc.validate {
					assert.Equal(t, osDigest, lineage.Digest)
				}
				return
			}
			assert.Nil(t, patched, "the image must be patched as supplied")
			assert.Equal(t, app, image)
			assert.Equal(t, &types.SourceLineage{Kind: types.PatchOriginImage, Name: app, Digest: appDigest}, lineage)
			assert.Equal(t, appLocal, got["BaseImage"], "BaseImage names the supplied image")
			assert.Equal(t, "kept", got["com.example.app"])
			for key := range osOrigin {
				assert.NotContains(t, got, key, "inherited origin labels must not describe the output")
			}
			var want, layers imageLayersConfig
			require.NoError(t, json.Unmarshal(tc.input, &want))
			require.NoError(t, json.Unmarshal(config, &layers))
			assert.Equal(t, want, layers, "the supplied image's layers are kept")
		})
	}
}

// Language-only patching starts from ImageState, so a derived image must be
// read as supplied, not through the OS base named by its inherited label.
func TestInitializeBuildkitConfigReadsDerivedImageAsSupplied(t *testing.T) {
	const (
		app    = "example.com/app:1.0"
		osBase = "example.com/os:base"
	)
	appDigest, osDigest := digest.FromString("app 1.0"), digest.FromString("os base")
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	runtime := []byte(`{"os":"linux","architecture":"amd64","config":{"Labels":{}}}`)
	appConfig, err := AddImageConfigLabels(
		withTestLayers(t, runtime, testOriginalLayer, testPatchLayer, testDerivedLayer),
		map[string]string{"BaseImage": osBase},
	)
	require.NoError(t, err)
	appRef := "example.com/app@" + appDigest.String()
	gateway := &locatorGateway{t: t, images: map[string]locatorMetadata{
		app:    {appDigest, appConfig},
		appRef: {appDigest, appConfig},
		osBase: {osDigest, originalTestConfig(t, runtime)},
	}}

	cfg, err := InitializeBuildkitConfig(t.Context(), gateway, app, platform)
	require.NoError(t, err)
	require.Nil(t, cfg.PatchedConfigData)
	require.Equal(t, appRef, stateSource(t, &cfg.ImageState, platform))
	require.Equal(t, app, configLabels(t, cfg.ConfigData)["BaseImage"])
	require.Equal(t, &types.SourceLineage{Kind: types.PatchOriginImage, Name: app, Digest: appDigest}, cfg.SourceLineage)
}
