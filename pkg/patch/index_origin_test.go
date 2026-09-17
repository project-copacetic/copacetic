package patch

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestRecordedIndexRejectsContradictoryChildrenBeforePatching(t *testing.T) {
	originalResolver, originalReader, originalBuilder := resolveImageSource, readIndexChildMetadata, bkNewClient
	t.Cleanup(func() {
		resolveImageSource, readIndexChildMetadata, bkNewClient = originalResolver, originalReader, originalBuilder
	})
	platform := specs.Platform{OS: "linux", Architecture: "amd64"}
	indexDigest, childDigest := digest.FromString("original index"), digest.FromString("original child")
	const input = "registry.example.com/app:patched"
	parent := &types.SourceLineage{Kind: types.PatchOriginImage, Name: "registry.example.com/app:original", Digest: indexDigest}
	origin := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: parent.Name, Digest: childDigest}).Annotations()
	for _, surface := range []string{"descriptor", "manifest", "config"} {
		for _, mismatch := range []string{"repository", "digest", "invalid", "partial"} {
			t.Run(surface+"/"+mismatch, func(t *testing.T) {
				claims := maps.Clone(origin)
				switch mismatch {
				case "repository":
					claims[types.AnnotationPatchOriginName] = "registry.example.com/different:original"
				case "digest":
					claims[types.AnnotationPatchOriginDigest] = digest.FromString("different child").String()
				case "invalid":
					claims[types.AnnotationPatchOriginKind] = "invalid"
				case "partial":
					delete(claims, types.AnnotationPatchOriginDigest)
				}
				current := &buildkit.ImageSource{Name: input, Index: &specs.Index{Annotations: parent.Annotations(), Manifests: []specs.Descriptor{{
					Digest: digest.FromString("patched child"), MediaType: specs.MediaTypeImageManifest, Platform: &platform, Annotations: origin,
				}}}}
				if surface == "descriptor" {
					current.Index.Manifests[0].Annotations = claims
				}
				base := &buildkit.ImageSource{Name: parent.Name, Descriptor: specs.Descriptor{Digest: indexDigest}, Index: &specs.Index{Manifests: []specs.Descriptor{{Digest: childDigest, Platform: &platform}}}}
				resolveImageSource = func(_ context.Context, image string) (*buildkit.ImageSource, error) {
					if image == input {
						return current, nil
					}
					return base, nil
				}
				readIndexChildMetadata = func(_ context.Context, image string) (map[string]string, map[string]string, error) {
					require.Equal(t, "registry.example.com/app@"+current.Index.Manifests[0].Digest.String(), image)
					if surface == "manifest" {
						return claims, origin, nil
					}
					if surface == "config" {
						return origin, claims, nil
					}
					return origin, origin, nil
				}
				builds := 0
				bkNewClient = func(context.Context, buildkit.Opts) (*client.Client, error) {
					builds++
					return nil, errors.New("unexpected build")
				}
				_, err := captureMultiPlatformSource(t.Context(), input)
				require.ErrorIs(t, err, errRecordedIndexOrigin)
				inputRef, err := reference.ParseNormalizedNamed(input)
				require.NoError(t, err)
				_, _, _, err = captureSinglePlatformSource(t.Context(), input, inputRef, &platform)
				require.ErrorIs(t, err, errRecordedIndexOrigin)
				err = patchMultiPlatformImage(t.Context(), &types.Options{Image: input, IgnoreError: true}, []types.PatchPlatform{{Platform: platform}})
				require.ErrorIs(t, err, errRecordedIndexOrigin)
				require.Zero(t, builds)
			})
		}
	}
}

func TestRecordedIndexAllowsUnverifiedPreservedChildren(t *testing.T) {
	reader := readIndexChildMetadata
	t.Cleanup(func() { readIndexChildMetadata = reader })
	platform := specs.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}
	original := digest.FromString("original child")
	parent := &types.SourceLineage{Kind: types.PatchOriginImage, Name: "example.com/app:original", Digest: digest.FromString("index")}
	child := &types.SourceLineage{Kind: types.PatchOriginImage, Name: parent.Name, Digest: original}
	source := &multiPlatformSource{
		Current: &buildkit.ImageSource{Name: "example.com/app:patched", Index: &specs.Index{Manifests: []specs.Descriptor{{
			Digest: digest.FromString("preserved patched child"), MediaType: specs.MediaTypeImageManifest, Platform: &platform,
		}}}},
		Base: &buildkit.ImageSource{Index: &specs.Index{Manifests: []specs.Descriptor{{Digest: original, Platform: &platform}}}}, IndexLineage: parent,
	}
	for _, claims := range []map[string]string{nil, child.Annotations(), parent.Annotations()} {
		readIndexChildMetadata = func(context.Context, string) (map[string]string, map[string]string, error) {
			labels := maps.Clone(claims)
			if labels == nil {
				labels = map[string]string{}
			}
			labels["BaseImage"] = parent.Name
			return claims, labels, nil
		}
		require.NoError(t, validateRecordedIndexChildren(t.Context(), source))
		require.Nil(t, commonBaseIndexLineage(source, []types.PatchResult{{PatchedDesc: &source.Current.Index.Manifests[0]}}), "matching unverified ancestry remains insufficient for output common claim")
	}
	readIndexChildMetadata = func(context.Context, string) (map[string]string, map[string]string, error) { return nil, nil, nil }
	require.ErrorContains(t, validateRecordedIndexChildren(t.Context(), source), "unpatched manifest contradicts")
	source.Current.Index.Manifests[0].Digest = original
	readIndexChildMetadata = func(context.Context, string) (map[string]string, map[string]string, error) {
		return nil, nil, nil
	}
	require.NoError(t, validateRecordedIndexChildren(t.Context(), source))
}
