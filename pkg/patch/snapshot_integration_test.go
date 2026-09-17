package patch

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/require"
)

// Reuse the actual frontend outputs produced earlier in TestOriginRoundTrip.
func testOriginSnapshotFollowups(t *testing.T, ctx context.Context, addr, repo string, images map[string]v1.Image, application map[string]string) {
	t.Helper()
	t.Run("frontend-common-index", func(t *testing.T) {
		original, err := remote.Index(originTestReference(t, repo+":original"), remote.WithContext(ctx))
		require.NoError(t, err)
		originalDigest, err := original.Digest()
		require.NoError(t, err)
		origin := &types.SourceLineage{Kind: types.PatchOriginImage, Name: repo + ":original", Digest: digest.Digest(originalDigest.String())}
		var children []mutate.IndexAddendum
		reports := t.TempDir()
		for _, arch := range []string{originAMD64, "386"} {
			img, err := remote.Image(originTestReference(t, repo+":frontend-"+arch+"-index-p3"), remote.WithContext(ctx), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: arch}))
			require.NoError(t, err)
			children = append(children, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
			report, err := os.ReadFile(originTestReport(t, arch))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(reports, arch+".json"), report, 0o600))
		}
		index := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, children...), v1types.OCIImageIndex)
		annotations := maps.Clone(application)
		maps.Copy(annotations, origin.Annotations())
		index, ok := mutate.Annotations(index, annotations).(v1.ImageIndex)
		require.True(t, ok)
		input := repo + ":frontend-common-input"
		require.NoError(t, remote.WriteIndex(originTestReference(t, input), index, remote.WithContext(ctx)))
		require.NoError(t, Patch(ctx, &types.Options{
			Image: input, Report: reports, Scanner: "trivy", Push: true, PatchedTag: "frontend-common-output",
			BkAddr: addr, PkgTypes: "os", Progress: "quiet", Timeout: 2 * time.Minute,
		}))
		output, err := remote.Index(originTestReference(t, repo+":frontend-common-output"), remote.WithContext(ctx))
		require.NoError(t, err)
		manifest, err := output.IndexManifest()
		require.NoError(t, err)
		for key, value := range annotations {
			require.Equal(t, value, manifest.Annotations[key])
		}
		require.Len(t, manifest.Manifests, 2)
		for i := range manifest.Manifests {
			require.Equal(t, origin.Digest.String(), manifest.Manifests[i].Annotations[types.AnnotationPatchOriginDigest])
		}
	})
	t.Run("no-update-snapshot", func(t *testing.T) {
		current, err := remote.Image(originTestReference(t, repo+":frontend-amd64-index-p3"), remote.WithContext(ctx))
		require.NoError(t, err)
		captured, err := current.Digest()
		require.NoError(t, err)
		source := repo + "@" + captured.String()
		mutable := repo + ":no-update-moved"
		replacement := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: images[originAMD64], Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: originAMD64}}})
		require.NoError(t, remote.WriteIndex(originTestReference(t, mutable), replacement, remote.WithContext(ctx)))
		for _, stage := range []string{"client-error", "empty-report", "after-solve"} {
			t.Run(stage, func(t *testing.T) {
				originalBuilder := bkNewClient
				t.Cleanup(func() { bkNewClient = originalBuilder })
				opts := &types.Options{Image: mutable, Push: true, PatchedTag: "no-update-" + stage, BkAddr: addr, PkgTypes: "os", Progress: "quiet"}
				var updates *unversioned.UpdateManifest
				if stage != "after-solve" {
					opts.Report = "already-parsed"
					updates = &unversioned.UpdateManifest{}
				}
				if stage == "client-error" {
					bkNewClient = func(context.Context, buildkit.Opts) (*client.Client, error) {
						return nil, errors.New("test connection failure")
					}
				}
				result, err := patchSingleArchImageWithSourceAndUpdates(ctx, opts, types.PatchPlatform{Platform: specs.Platform{OS: "linux", Architecture: originAMD64}}, true, nil, updates, source, nil)
				require.ErrorIs(t, err, types.ErrNoUpdatesFound)
				require.NotNil(t, result)
				require.NotNil(t, result.PatchedDesc)
				require.Equal(t, captured.String(), result.PatchedDesc.Digest.String(), "a moved tag must not replace an up-to-date captured platform")
				require.Equal(t, mutable, result.OriginalRef.String())
				_, err = remote.Get(originTestReference(t, repo+":"+opts.PatchedTag+"-amd64"), remote.WithContext(ctx))
				require.Error(t, err, "no-update work must not publish a platform image")
			})
		}
	})
	t.Run("annotation-snapshot", func(t *testing.T) {
		childAnnotations := maps.Clone(application)
		childAnnotations["com.example.snapshot"] = "captured child"
		child := originAnnotatedImage(t, images[originAMD64], childAnnotations)
		captured, err := child.Digest()
		require.NoError(t, err)
		mutable := repo + ":annotations-moved"
		require.NoError(t, remote.Write(originTestReference(t, mutable), child, remote.WithContext(ctx)))
		replacement := originAnnotatedImage(t, images[originAMD64], map[string]string{"com.example.snapshot": "moved tag", "com.example.moved-only": "unrelated"})
		require.NoError(t, remote.Write(originTestReference(t, mutable), replacement, remote.WithContext(ctx)))
		descriptorAnnotations := map[string]string{"com.example.snapshot": "parent descriptor", "com.example.descriptor-only": "captured parent"}
		opts := &types.Options{Image: mutable, Report: originTestReport(t, originAMD64), Scanner: "trivy", Push: true, PatchedTag: "annotations-captured", BkAddr: addr, PkgTypes: "os", Progress: "quiet"}
		result, err := patchSingleArchImageWithSource(ctx, opts,
			types.PatchPlatform{Platform: specs.Platform{OS: "linux", Architecture: originAMD64}}, true, nil, repo+"@"+captured.String(), descriptorAnnotations)
		require.NoError(t, err)
		output, err := remote.Image(originTestReference(t, result.PatchedRef.String()), remote.WithContext(ctx))
		require.NoError(t, err)
		manifest, err := output.Manifest()
		require.NoError(t, err)
		for key, value := range childAnnotations {
			require.Equal(t, value, manifest.Annotations[key])
		}
		require.Equal(t, "captured parent", manifest.Annotations["com.example.descriptor-only"])
		require.NotContains(t, manifest.Annotations, "com.example.moved-only")
		require.Equal(t, "parent descriptor", descriptorAnnotations["com.example.snapshot"], "capture must not be mutated")
	})
	t.Run("exact-child-metadata", func(t *testing.T) {
		for _, surface := range []string{originManifestSurface, originConfigSurface} {
			t.Run(surface, func(t *testing.T) {
				badOrigin := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: repo + ":original", Digest: digest.FromString("contradictory original")}).Annotations()
				child := images[originAMD64]
				if surface == originManifestSurface {
					annotations := maps.Clone(application)
					maps.Copy(annotations, badOrigin)
					child = originAnnotatedImage(t, child, annotations)
				} else {
					cfg, err := child.ConfigFile()
					require.NoError(t, err)
					cfg = cfg.DeepCopy()
					if cfg.Config.Labels == nil {
						cfg.Config.Labels = map[string]string{}
					}
					maps.Copy(cfg.Config.Labels, badOrigin)
					child, err = mutate.ConfigFile(child, cfg)
					require.NoError(t, err)
				}
				for _, count := range []int{1, 2} {
					children := []mutate.IndexAddendum{{Add: child, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: originAMD64}}}}
					if count == 2 {
						children = append(children, mutate.IndexAddendum{Add: images["386"], Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "386"}}})
					}
					base := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, children...), v1types.OCIImageIndex)
					baseDigest, err := base.Digest()
					require.NoError(t, err)
					baseName := fmt.Sprintf("%s:exact-base-%s-%d", repo, surface, count)
					require.NoError(t, remote.WriteIndex(originTestReference(t, baseName), base, remote.WithContext(ctx)))
					origin := (&types.SourceLineage{Kind: types.PatchOriginImage, Name: baseName, Digest: digest.Digest(baseDigest.String())}).Annotations()
					current, ok := mutate.Annotations(base, origin).(v1.ImageIndex)
					require.True(t, ok)
					input := fmt.Sprintf("%s:exact-current-%s-%d", repo, surface, count)
					require.NoError(t, remote.WriteIndex(originTestReference(t, input), current, remote.WithContext(ctx)))
					output := fmt.Sprintf("exact-rejected-%s-%d", surface, count)
					err = Patch(ctx, &types.Options{Image: input, Push: true, PatchedTag: output, BkAddr: addr, PkgTypes: "os", IgnoreError: true, Progress: "quiet", Timeout: time.Minute})
					require.ErrorIs(t, err, errRecordedIndexOrigin)
					for _, suffix := range []string{"", "-amd64", "-386"} {
						ref, err := name.ParseReference(repo + ":" + output + suffix)
						require.NoError(t, err)
						_, err = remote.Get(ref, remote.WithContext(ctx))
						require.Error(t, err, "contradictory exact children must fail before outputs")
					}
				}
			})
		}
	})
}
