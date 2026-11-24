package buildkit

import (
	"encoding/json"
	"maps"
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

func TestClassifyPatchLayers(t *testing.T) {
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
		want    patchLayers
		wantErr string
	}{
		{
			name:  "re-patch output adds one patch layer",
			input: withTestLayers(t, base, testOriginalLayer, testPatchLayer),
			base:  originalTestConfig(t, base),
			want:  patchLayersCopaOutput,
		},
		{
			name:  "first patch output may add several patch layers",
			input: withTestLayers(t, base, testOriginalLayer, testPatchLayer, testPatchLayer2),
			base:  originalTestConfig(t, base),
			want:  patchLayersCopaOutput,
		},
		{
			name:  "output with no patch layers has the base layers",
			input: originalTestConfig(t, base),
			base:  originalTestConfig(t, base),
			want:  patchLayersCopaOutput,
		},
		{
			name:  "empty-layer history entries are not layers",
			input: withHistory(copaOutputTestConfig(t, base), emptyLayer),
			base:  originalTestConfig(t, base),
			want:  patchLayersCopaOutput,
		},
		{
			name:    "image built FROM a Copa output has its own layers",
			input:   withTestLayers(t, base, testOriginalLayer, testPatchLayer, testDerivedLayer),
			base:    originalTestConfig(t, base),
			want:    patchLayersDerived,
			wantErr: "layer 2 above the base image's layers was not added by a Copa patch",
		},
		{
			name:    "layers added by another builder are not a patch",
			input:   withTestLayers(t, base, testOriginalLayer, testLayer{digest.FromString("docker commit"), ""}),
			base:    originalTestConfig(t, base),
			want:    patchLayersDerived,
			wantErr: "layer 1 above the base image's layers was not added by a Copa patch",
		},
		{
			name:    "history that does not describe each layer",
			input:   withHistory(withTestLayers(t, base, testOriginalLayer, testPatchLayer), specs.History{Comment: exporterHistoryComment}),
			base:    originalTestConfig(t, base),
			want:    patchLayersDerived,
			wantErr: "history does not describe each of its layers",
		},
		{
			name:    "image not built on the base",
			input:   withTestLayers(t, base, testDerivedLayer, testPatchLayer),
			base:    originalTestConfig(t, base),
			want:    patchLayersNotOnBase,
			wantErr: "do not start with the base image's layers",
		},
		{
			name:    "image with fewer layers than the base",
			input:   originalTestConfig(t, base),
			base:    copaOutputTestConfig(t, base),
			want:    patchLayersNotOnBase,
			wantErr: "do not start with the base image's layers",
		},
		{
			name:    "input without a rootfs",
			input:   base,
			base:    originalTestConfig(t, base),
			want:    patchLayersNotOnBase,
			wantErr: "cannot be compared",
		},
		{
			name:    "base without a rootfs",
			input:   copaOutputTestConfig(t, base),
			base:    base,
			want:    patchLayersNotOnBase,
			wantErr: "cannot be compared",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := classifyPatchLayers(tc.input, tc.base)
			assert.Equal(t, tc.want, got)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// How an input carrying a BaseImage label is patched.
const (
	wantRepatch      = "re-patch from the recorded base"
	wantSupplied     = "patch as supplied"
	wantCurrentImage = "keep the current image without an origin"
)

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
		name    string
		input   []byte
		want    string
		wantErr string
	}{
		{
			name:  "derived from a legacy Copa output",
			input: labels(t, withTestLayers(t, runtime, testOriginalLayer, testPatchLayer, testDerivedLayer), legacy),
			want:  wantSupplied,
		},
		{
			name:  "derived from a Copa output with origin labels",
			input: labels(t, withTestLayers(t, runtime, testOriginalLayer, testPatchLayer, testDerivedLayer), withOrigin),
			want:  wantSupplied,
		},
		{
			// A released Copa output whose BaseImage tag now names a rebuild.
			name:  "legacy Copa output whose BaseImage tag has moved",
			input: labels(t, withTestLayers(t, runtime, testLayer{digest.FromString("older OS layer"), ""}, testPatchLayer), legacy),
			want:  wantCurrentImage,
		},
		{
			name:    "image not built on its recorded origin",
			input:   labels(t, withTestLayers(t, runtime, testLayer{digest.FromString("older OS layer"), ""}, testPatchLayer), withOrigin),
			wantErr: "image is not built on its recorded patch origin",
		},
		{
			name:  "legacy Copa output",
			input: labels(t, copaOutputTestConfig(t, runtime), legacy),
			want:  wantRepatch,
		},
		{
			name:  "Copa output with origin labels",
			input: labels(t, copaOutputTestConfig(t, runtime), withOrigin),
			want:  wantRepatch,
		},
		{
			name:  "Copa output with several first-patch layers",
			input: labels(t, withTestLayers(t, runtime, testOriginalLayer, testPatchLayer, testPatchLayer2), withOrigin),
			want:  wantRepatch,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &mocks.MockGWClient{}
			client.On("ResolveImageConfig", mock.Anything, osBase, mock.Anything).
				Return(osBase, osDigest, baseConfig, nil).Once()
			_, hasOrigin := configLabels(t, tc.input)[types.AnnotationPatchOriginDigest]

			config, patched, image, lineage, validated, err := updateImageConfigData(t.Context(), client, tc.input, app, appLocal, appDigest, platform)
			client.AssertExpectations(t)
			if tc.wantErr != "" {
				require.ErrorIs(t, err, ErrOriginIntegrity)
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			got := configLabels(t, config)
			switch tc.want {
			case wantRepatch:
				assert.Equal(t, osBase, image, "a Copa output is re-patched from its recorded base")
				assert.Equal(t, tc.input, patched)
				assert.Equal(t, osBase, got["BaseImage"])
				assert.Equal(t, hasOrigin, validated)
				if hasOrigin {
					assert.Equal(t, osDigest, lineage.Digest)
				} else {
					assert.Nil(t, lineage)
				}
				return
			case wantCurrentImage:
				assert.Nil(t, patched)
				assert.Equal(t, app, image)
				assert.Nil(t, lineage, "neither the image nor the moved tag is a verified origin")
				assert.False(t, validated)
				assert.Equal(t, appLocal, got["BaseImage"])
			case wantSupplied:
				assert.Nil(t, patched, "the image must be patched as supplied")
				assert.Equal(t, app, image)
				assert.Equal(t, &types.SourceLineage{Kind: types.PatchOriginImage, Name: app, Digest: appDigest}, lineage)
				assert.False(t, validated)
				assert.Equal(t, appLocal, got["BaseImage"], "BaseImage names the supplied image")
				for key := range osOrigin {
					assert.NotContains(t, got, key, "inherited origin labels must not describe the output")
				}
			default:
				t.Fatalf("unknown expectation %q", tc.want)
			}
			assert.Equal(t, "kept", got["com.example.app"])
			var want, layers imageLayersConfig
			require.NoError(t, json.Unmarshal(tc.input, &want))
			require.NoError(t, json.Unmarshal(config, &layers))
			assert.Equal(t, want, layers, "the supplied image's layers are kept")
		})
	}
}

// The output of patching a derived image as supplied records that image as its
// origin, and the origin still carries the BaseImage label it inherited. That
// output must re-patch from the derived image, and an image built FROM the
// output must in turn be patched as supplied.
func TestRepatchOutputOfDerivedImage(t *testing.T) {
	const (
		osBase  = "registry.example/os:base"
		app     = "registry.example/app:1.0"
		patched = "registry.example/app:1.0-patched"
		app2    = "registry.example/app2:1.0"
	)
	osDigest, appDigest := digest.FromString("os base"), digest.FromString("app 1.0")
	patchedDigest, app2Digest := digest.FromString("app 1.0-patched"), digest.FromString("app2 1.0")
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	runtime := []byte(`{"os":"linux","architecture":"amd64","config":{"Labels":{"com.example.app":"kept"}}}`)
	osOrigin := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: osBase, Digest: osDigest}).Annotations()
	withLabels := func(t *testing.T, config []byte, labels map[string]string) []byte {
		t.Helper()
		updated, err := AddImageConfigLabels(config, labels)
		require.NoError(t, err)
		return updated
	}
	derivedLayers := []testLayer{testOriginalLayer, testPatchLayer, testDerivedLayer}

	for _, tc := range []struct {
		name   string
		labels map[string]string
	}{
		{name: "legacy", labels: map[string]string{"BaseImage": osBase}},
		{name: "origin labels", labels: func() map[string]string {
			labels := map[string]string{"BaseImage": osBase}
			for key, value := range osOrigin {
				labels[key] = value
			}
			return labels
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			appConfig := withLabels(t, withTestLayers(t, runtime, derivedLayers...), tc.labels)
			first := &mocks.MockGWClient{}
			first.On("ResolveImageConfig", mock.Anything, osBase, mock.Anything).
				Return(osBase, osDigest, originalTestConfig(t, runtime), nil).Once()
			firstConfig, firstPatched, _, firstLineage, _, err := updateImageConfigData(t.Context(), first, appConfig, app, app, appDigest, platform)
			require.NoError(t, err)
			require.Nil(t, firstPatched)
			first.AssertExpectations(t)

			// Emulate the export: Copa writes the origin labels and BuildKit adds
			// the patch layer with an exporter history entry.
			output := withLabels(t, withTestLayers(t, firstConfig, append(derivedLayers, testPatchLayer2)...), firstLineage.Annotations())

			// Re-patching the output recovers app:1.0 although it carries the
			// BaseImage label it inherited from the OS image.
			second := &mocks.MockGWClient{}
			second.On("ResolveImageConfig", mock.Anything, app, mock.Anything).Return(app, appDigest, appConfig, nil)
			config, previous, image, lineage, validated, err := updateImageConfigData(t.Context(), second, output, patched, patched, patchedDigest, platform)
			require.NoError(t, err)
			assert.Equal(t, app, image)
			assert.Equal(t, output, previous)
			assert.Equal(t, firstLineage, lineage)
			assert.True(t, validated)
			got := configLabels(t, config)
			assert.Equal(t, app, got["BaseImage"])
			for key := range osOrigin {
				assert.NotContains(t, got, key, "app:1.0's inherited origin labels must not describe the output")
			}

			// An image built FROM the output has layers of its own above it.
			app2Config := withTestLayers(t, output, append(derivedLayers, testPatchLayer2, testLayer{digest.FromString("app2 layer"), "buildkit.dockerfile.v0"})...)
			config, previous, image, lineage, validated, err = updateImageConfigData(t.Context(), second, app2Config, app2, app2, app2Digest, platform)
			require.NoError(t, err)
			assert.Nil(t, previous)
			assert.Equal(t, app2, image)
			assert.Equal(t, &types.SourceLineage{Kind: types.PatchOriginImage, Name: app2, Digest: app2Digest}, lineage)
			assert.False(t, validated)
			assert.Equal(t, app2, configLabels(t, config)["BaseImage"])
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

// A recorded origin with a BaseImage label is accepted only when it is an image
// built FROM a Copa output and patched as supplied, so its top layer is its
// own. An origin whose top layer is a Copa patch layer is itself a Copa output,
// even when the input is built on it.
func TestUpdateImageConfigDataChecksOriginWithBaseImage(t *testing.T) {
	const (
		originRef = "registry.example/os:patched"
		app       = "registry.example/app:1.0-patched"
	)
	originDigest := digest.FromString("os patched")
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	originLabels := []byte(`{"os":"linux","architecture":"amd64","config":{"Labels":{"BaseImage":"registry.example/os:base"}}}`)
	inputLabels := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: originRef, Digest: originDigest}).Annotations()
	inputLabels["BaseImage"] = originRef
	input := func(t *testing.T, layers ...testLayer) []byte {
		t.Helper()
		config, err := AddImageConfigLabels(withTestLayers(t, []byte(`{"os":"linux","architecture":"amd64","config":{}}`), layers...), inputLabels)
		require.NoError(t, err)
		return config
	}
	otherLayer := testLayer{digest.FromString("other OS layer"), ""}

	for _, tc := range []struct {
		name    string
		origin  []byte
		input   []byte
		wantErr []string
	}{
		{
			name:    "Copa output as origin with the input equal to it",
			origin:  copaOutputTestConfig(t, originLabels),
			input:   input(t, testOriginalLayer, testPatchLayer),
			wantErr: []string{"recorded patch origin is itself a Copa-patched image"},
		},
		{
			name:    "Copa output as origin with a patch layer above it",
			origin:  copaOutputTestConfig(t, originLabels),
			input:   input(t, testOriginalLayer, testPatchLayer, testPatchLayer2),
			wantErr: []string{"recorded patch origin is itself a Copa-patched image"},
		},
		{
			name:    "origin with a BaseImage label and no layers",
			origin:  originLabels,
			input:   input(t, testOriginalLayer, testPatchLayer),
			wantErr: []string{"recorded patch origin is itself a Copa-patched image"},
		},
		{
			// The exporter gives every layer a history entry, so an origin
			// without history was built by another tool, not patched by Copa.
			name: "derived origin without history",
			origin: func() []byte {
				var image map[string]any
				require.NoError(t, json.Unmarshal(withTestLayers(t, originLabels, testOriginalLayer, testPatchLayer, testDerivedLayer), &image))
				delete(image, "history")
				config, err := json.Marshal(image)
				require.NoError(t, err)
				return config
			}(),
			input: input(t, testOriginalLayer, testPatchLayer, testDerivedLayer, testPatchLayer2),
		},
		{
			name: "derived origin with history for only some layers",
			origin: func() []byte {
				var image specs.Image
				require.NoError(t, json.Unmarshal(withTestLayers(t, originLabels, testOriginalLayer, testPatchLayer, testDerivedLayer), &image))
				image.History = image.History[:1]
				config, err := json.Marshal(image)
				require.NoError(t, err)
				return config
			}(),
			input: input(t, testOriginalLayer, testPatchLayer, testDerivedLayer, testPatchLayer2),
		},
		{
			name:   "derived origin that the input is not built on",
			origin: withTestLayers(t, originLabels, testOriginalLayer, testPatchLayer, testDerivedLayer),
			input:  input(t, otherLayer, testPatchLayer2),
			wantErr: []string{
				"image is not built on its recorded patch origin",
				"the recorded origin has its own BaseImage label registry.example/os:base",
				`LABEL BaseImage="" sh.copa.patch.origin.kind=""`,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &mocks.MockGWClient{}
			client.On("ResolveImageConfig", mock.Anything, originRef, mock.Anything).Return(originRef, originDigest, tc.origin, nil).Once()

			_, patched, _, lineage, validated, err := updateImageConfigData(t.Context(), client, tc.input, app, app, digest.FromString(app), platform)
			client.AssertExpectations(t)
			if len(tc.wantErr) == 0 {
				require.NoError(t, err)
				assert.Equal(t, tc.input, patched, "the input is re-patched from its origin")
				assert.Equal(t, originDigest, lineage.Digest)
				assert.True(t, validated)
				return
			}
			require.ErrorIs(t, err, ErrOriginIntegrity)
			for _, want := range tc.wantErr {
				require.ErrorContains(t, err, want)
			}
		})
	}
}

// A Dockerfile cannot remove an inherited label, only set it to an empty value,
// so empty BaseImage and origin labels count as absent.
func TestUpdateImageConfigDataTreatsEmptyLabelsAsAbsent(t *testing.T) {
	const (
		osBase = "registry.example/os:base"
		app    = "registry.example/app:1.0"
	)
	appDigest := digest.FromString("app 1.0")
	platform := &specs.Platform{OS: "linux", Architecture: "amd64"}
	runtime := []byte(`{"os":"linux","architecture":"amd64","config":{}}`)
	derived := withTestLayers(t, runtime, testOriginalLayer, testPatchLayer, testDerivedLayer)
	cleared := map[string]string{
		types.AnnotationPatchOriginKind:   "",
		types.AnnotationPatchOriginName:   "",
		types.AnnotationPatchOriginDigest: "",
	}
	withLabels := func(t *testing.T, labels map[string]string, extra ...string) []byte {
		t.Helper()
		labels = maps.Clone(labels)
		for i := 0; i < len(extra); i += 2 {
			labels[extra[i]] = extra[i+1]
		}
		config, err := AddImageConfigLabels(derived, labels)
		require.NoError(t, err)
		return config
	}

	for _, tc := range []struct {
		name        string
		input       []byte
		resolveBase bool
		wantErr     string
	}{
		{
			name:  "all labels cleared is a first patch",
			input: withLabels(t, cleared, "BaseImage", ""),
		},
		{
			name:        "cleared origin labels leave a legacy BaseImage",
			input:       withLabels(t, cleared, "BaseImage", osBase),
			resolveBase: true,
		},
		{
			name:    "a partly cleared origin is still invalid",
			input:   withLabels(t, cleared, "BaseImage", "", types.AnnotationPatchOriginKind, types.PatchOriginImage),
			wantErr: "invalid patch origin metadata",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &mocks.MockGWClient{}
			if tc.resolveBase {
				client.On("ResolveImageConfig", mock.Anything, osBase, mock.Anything).
					Return(osBase, digest.FromString("os base"), originalTestConfig(t, runtime), nil).Once()
			}

			config, patched, image, lineage, validated, err := updateImageConfigData(t.Context(), client, tc.input, app, app, appDigest, platform)
			client.AssertExpectations(t)
			if tc.wantErr != "" {
				require.ErrorIs(t, err, ErrOriginIntegrity)
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Nil(t, patched)
			assert.Equal(t, app, image)
			assert.Equal(t, &types.SourceLineage{Kind: types.PatchOriginImage, Name: app, Digest: appDigest}, lineage)
			assert.False(t, validated)
			assert.Equal(t, app, configLabels(t, config)["BaseImage"])
		})
	}
}
