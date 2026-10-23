package patch

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

// countingLocalSource stands in for one operation's shared local archive.
type countingLocalSource struct {
	image       string
	root        digest.Digest
	annotations map[digest.Digest]map[string]string
	manifests   map[digest.Digest][]byte
	configs     map[digest.Digest][]byte
	lookups     []string
}

func (s *countingLocalSource) ManifestAnnotations(_ context.Context, image string, selected digest.Digest) (map[string]string, error) {
	s.lookups = append(s.lookups, "annotations "+image)
	return s.annotations[selected], nil
}

func (s *countingLocalSource) Metadata(_ context.Context, parent string, selected digest.Digest) (*remote.Descriptor, []byte, error) {
	s.lookups = append(s.lookups, "metadata "+parent)
	manifest := s.manifests[selected]
	if manifest == nil {
		return nil, nil, nil
	}
	return &remote.Descriptor{Manifest: manifest}, s.configs[selected], nil
}

type sharedSourceIndex struct {
	source      *buildkit.ImageSource
	platforms   []types.PatchPlatform
	refs        map[string]string
	descriptors map[string]*specs.Descriptor
	manifests   map[digest.Digest][]byte
	configs     map[digest.Digest][]byte
}

// newSharedSourceIndex is a local index of eight platforms. The first two are
// patched and the others are preserved, as with a report for two platforms.
func newSharedSourceIndex(t *testing.T, name string, annotations map[string]string) *sharedSourceIndex {
	t.Helper()
	arches := []string{"amd64", "386", "arm64", "arm", "ppc64le", "riscv64", "s390x", "mips64le"}
	index := &sharedSourceIndex{
		refs: map[string]string{}, descriptors: map[string]*specs.Descriptor{},
		manifests: map[digest.Digest][]byte{}, configs: map[digest.Digest][]byte{},
	}
	children := make([]specs.Descriptor, 0, len(arches))
	for i, arch := range arches {
		config, err := json.Marshal(specs.Image{Platform: specs.Platform{OS: LINUX, Architecture: arch}})
		require.NoError(t, err)
		manifest, err := json.Marshal(specs.Manifest{
			Versioned: ocispec.Versioned{SchemaVersion: 2}, MediaType: specs.MediaTypeImageManifest,
			Config: specs.Descriptor{MediaType: specs.MediaTypeImageConfig, Digest: digest.FromBytes(config), Size: int64(len(config))},
		})
		require.NoError(t, err)
		p := specs.Platform{OS: LINUX, Architecture: arch}
		child := specs.Descriptor{MediaType: specs.MediaTypeImageManifest, Digest: digest.FromBytes(manifest), Size: int64(len(manifest)), Platform: &p}
		children = append(children, child)
		index.manifests[child.Digest], index.configs[child.Digest] = manifest, config
		key := buildkit.PlatformKey(p)
		index.platforms = append(index.platforms, types.PatchPlatform{Platform: p, ShouldPreserve: i >= 2})
		named, err := reference.ParseNormalizedNamed(name)
		require.NoError(t, err)
		pinned, err := reference.WithDigest(reference.TrimNamed(named), child.Digest)
		require.NoError(t, err)
		index.refs[key], index.descriptors[key] = pinned.String(), &children[len(children)-1]
	}
	body, err := json.Marshal(specs.Index{Versioned: ocispec.Versioned{SchemaVersion: 2}, MediaType: specs.MediaTypeImageIndex, Manifests: children, Annotations: annotations})
	require.NoError(t, err)
	index.source = &buildkit.ImageSource{
		Name:       name,
		Descriptor: specs.Descriptor{MediaType: specs.MediaTypeImageIndex, Digest: digest.FromBytes(body), Size: int64(len(body))},
		Index:      &specs.Index{Versioned: ocispec.Versioned{SchemaVersion: 2}, MediaType: specs.MediaTypeImageIndex, Manifests: children, Annotations: annotations},
	}
	return index
}

// Every patched platform's annotations and every preserved platform's origin
// check are served from one shared read of each locally named source.
func TestMultiPlatformSourceSharesOneLocalRead(t *testing.T) {
	resolver, descriptorLookup, factory := resolveImageSource, localPlatformDescriptor, newLocalSource
	t.Cleanup(func() {
		resolveImageSource, localPlatformDescriptor, newLocalSource = resolver, descriptorLookup, factory
	})

	var created []*countingLocalSource
	sources := map[string]*sharedSourceIndex{}
	newLocalSource = func(image string, root digest.Digest) localSource {
		shared := &countingLocalSource{image: image, root: root, manifests: map[digest.Digest][]byte{}, configs: map[digest.Digest][]byte{}}
		for _, index := range sources {
			if index.source.Name == image && index.source.Descriptor.Digest == root {
				shared.manifests, shared.configs = index.manifests, index.configs
			}
		}
		created = append(created, shared)
		return shared
	}
	resolveImageSource = func(_ context.Context, image string) (*buildkit.ImageSource, error) {
		for _, index := range sources {
			if index.source.Name == image {
				return index.source, nil
			}
		}
		t.Fatalf("unexpected source %s", image)
		return nil, nil
	}

	patchResults := func(index *sharedSourceIndex, origin *buildkit.ImageSource, originName string) []types.PatchResult {
		original, err := reference.ParseNormalizedNamed(index.source.Name)
		require.NoError(t, err)
		patched, err := reference.ParseNormalizedNamed(index.source.Name + "-patched")
		require.NoError(t, err)
		var items []types.PatchResult
		for _, p := range index.platforms {
			child := index.descriptors[buildkit.PlatformKey(p.Platform)]
			if p.ShouldPreserve {
				items = append(items, types.PatchResult{OriginalRef: original, PatchedRef: original, PatchedDesc: child})
				continue
			}
			expected, err := origin.PlatformDescriptor(&p.Platform)
			require.NoError(t, err)
			lineage := &types.SourceLineage{Kind: types.PatchOriginImage, Name: originName, Digest: expected.Digest}
			items = append(items, types.PatchResult{
				OriginalRef: original, PatchedRef: patched,
				PatchedDesc: &specs.Descriptor{Digest: digest.FromString("patched " + p.Architecture), Platform: &p.Platform, Annotations: lineage.Annotations()},
			})
		}
		return items
	}

	t.Run("unmarked local index", func(t *testing.T) {
		created, sources = nil, map[string]*sharedSourceIndex{}
		index := newSharedSourceIndex(t, "registry.example.com/app:local", nil)
		sources["current"] = index
		localPlatformDescriptor = func(_ context.Context, _ string, p *specs.Platform) (*specs.Descriptor, bool, error) {
			return index.descriptors[buildkit.PlatformKey(*p)], true, nil
		}

		source, err := captureMultiPlatformSource(t.Context(), index.source.Name)
		require.NoError(t, err)
		_, err = captureSelectedSourceAnnotations(t.Context(), index.source.Name, source.local, index.platforms, index.refs, index.descriptors)
		require.NoError(t, err)
		lineage := commonBaseIndexLineage(t.Context(), source, patchResults(index, index.source, index.source.Name))
		require.Equal(t, &types.SourceLineage{Kind: types.PatchOriginImage, Name: index.source.Name, Digest: index.source.Descriptor.Digest}, lineage)

		require.Len(t, created, 1, "one shared read per source")
		require.Equal(t, index.source.Descriptor.Digest, created[0].root)
		annotations, metadata := 0, 0
		for _, lookup := range created[0].lookups {
			switch lookup {
			case "annotations " + index.source.Name:
				annotations++
			case "metadata " + index.source.Name:
				metadata++
			default:
				t.Fatalf("unexpected lookup %q", lookup)
			}
		}
		require.Equal(t, 2, annotations, "each patched platform's annotations")
		require.Equal(t, 6, metadata, "each preserved platform's origin check")
	})

	t.Run("recorded original index", func(t *testing.T) {
		created, sources = nil, map[string]*sharedSourceIndex{}
		base := newSharedSourceIndex(t, "registry.example.com/app:1.0", nil)
		pinned, err := immutableLineageReference(&types.SourceLineage{Kind: types.PatchOriginImage, Name: base.source.Name, Digest: base.source.Descriptor.Digest})
		require.NoError(t, err)
		base.source.Name = pinned
		recorded := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: "registry.example.com/app:1.0", Digest: base.source.Descriptor.Digest}).Annotations()
		current := newSharedSourceIndex(t, "registry.example.com/app:repatch", recorded)
		sources["base"], sources["current"] = base, current

		source, err := captureMultiPlatformSource(t.Context(), current.source.Name)
		require.NoError(t, err)
		require.Same(t, base.source, source.Base)
		lineage := commonBaseIndexLineage(t.Context(), source, patchResults(current, base.source, "registry.example.com/app:1.0"))
		require.NotNil(t, lineage)

		require.Len(t, created, 2, "one shared read for the current and one for the original index")
		require.Equal(t, current.source.Descriptor.Digest, created[0].root)
		require.Equal(t, base.source.Descriptor.Digest, created[1].root)
		require.Len(t, created[0].lookups, len(current.platforms), "every recorded child is checked through the current index")
		for _, lookup := range created[0].lookups {
			require.Equal(t, "metadata "+current.source.Name, lookup)
		}
		require.Len(t, created[1].lookups, 6, "every preserved child is checked through the original index")
		for _, lookup := range created[1].lookups {
			require.Equal(t, "metadata "+pinned, lookup)
		}
	})

	t.Run("origin checks still apply to each platform", func(t *testing.T) {
		created, sources = nil, map[string]*sharedSourceIndex{}
		index := newSharedSourceIndex(t, "registry.example.com/app:local", nil)
		sources["current"] = index
		localPlatformDescriptor = func(_ context.Context, _ string, p *specs.Platform) (*specs.Descriptor, bool, error) {
			return index.descriptors[buildkit.PlatformKey(*p)], true, nil
		}
		source, err := captureMultiPlatformSource(t.Context(), index.source.Name)
		require.NoError(t, err)
		amd64 := index.descriptors[buildkit.PlatformKey(specs.Platform{OS: LINUX, Architecture: "amd64"})].Digest
		created[0].annotations = map[digest.Digest]map[string]string{amd64: {types.AnnotationPatchOriginKind: types.PatchOriginImage}}
		_, err = captureSelectedSourceAnnotations(t.Context(), index.source.Name, source.local, index.platforms, index.refs, index.descriptors)
		require.ErrorContains(t, err, "invalid patch origin")
	})
}
