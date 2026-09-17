package patch

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"maps"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/frontend"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/stretchr/testify/require"
	"github.com/tonistiigi/fsutil"
)

// TestOriginRoundTrip needs a real host-networked BuildKit builder and the
// serialized OCI proof lane. It patches real APK packages, exports them, then
// supplies the exported P1 to the second patch. No gateway/registry mocks are used.
// Set COPA_ORIGIN_BUILDKIT_ADDR and BUILDX_BUILDER to the disposable builder.
func TestOriginRoundTrip(t *testing.T) {
	addr := os.Getenv("COPA_ORIGIN_BUILDKIT_ADDR")
	if addr == "" {
		t.Skip("set COPA_ORIGIN_BUILDKIT_ADDR to run the real origin round trip")
	}
	// Unit-test initialization uses an unavailable client. This boundary test
	// must exercise the production factory for the public Patch entry point.
	originalNewClient := bkNewClient
	bkNewClient = buildkit.NewClient
	t.Cleanup(func() { bkNewClient = originalNewClient })
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Minute)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(registry.New(registry.Logger(stdlog.New(io.Discard, "", 0))))
	server.Listener = listener
	server.Start()
	defer server.Close()
	repo := listener.Addr().String() + "/copa-1678-origin"
	t.Logf("Origin test registry: %s", repo)
	bk, err := buildkit.NewClient(ctx, buildkit.Opts{Addr: addr})
	require.NoError(t, err)
	defer bk.Close()
	application := map[string]string{
		specs.AnnotationBaseImageName:   "example.com/application-base:stable",
		specs.AnnotationBaseImageDigest: digest.FromString("application B").String(),
	}
	images := map[string]v1.Image{}
	descriptors := map[string]specs.Descriptor{}
	var children []mutate.IndexAddendum
	for _, arch := range []string{"amd64", "386"} {
		img, err := remote.Image(originTestReference(t, "alpine:3.20.0"), remote.WithContext(ctx), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: arch}))
		require.NoError(t, err)
		cfg, err := img.ConfigFile()
		require.NoError(t, err)
		cfg.Config.Labels = maps.Clone(application)
		img, err = mutate.ConfigFile(img, cfg)
		require.NoError(t, err)
		img = originAnnotatedImage(t, mutate.MediaType(img, v1types.OCIManifestSchema1), application)
		images[arch] = img
		tag := originTestReference(t, repo+":original-"+arch)
		require.NoError(t, remote.Write(tag, img, remote.WithContext(ctx)))
		h, err := img.Digest()
		require.NoError(t, err)
		descriptors[arch] = specs.Descriptor{Digest: digest.Digest(h.String()), MediaType: specs.MediaTypeImageManifest, Platform: &specs.Platform{OS: "linux", Architecture: arch}}
		children = append(children, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}}})
	}
	// An unchanged platform's embedded attestation must survive a mixed layout.
	secondaryHash, err := images["386"].Digest()
	require.NoError(t, err)
	statement := []byte(fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v0.1",
 "subject":[{"name":"fixture","digest":{"sha256":"%s"}}],
 "predicateType":"https://example.invalid/origin-test","predicate":{}}`, secondaryHash.Hex))
	attestation, err := mutate.AppendLayers(empty.Image, static.NewLayer(statement, v1types.MediaType("application/vnd.in-toto+json")))
	require.NoError(t, err)
	attestation = mutate.MediaType(attestation, v1types.OCIManifestSchema1)
	children = append(children, mutate.IndexAddendum{Add: attestation, Descriptor: v1.Descriptor{
		Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
		Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": secondaryHash.String()},
	}})
	index := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, children...), v1types.OCIImageIndex)
	annotatedIndex, ok := mutate.Annotations(index, application).(v1.ImageIndex)
	require.True(t, ok)
	index = annotatedIndex
	originalTag := originTestReference(t, repo+":original")
	require.NoError(t, remote.WriteIndex(originalTag, index, remote.WithContext(ctx)))
	source, err := captureMultiPlatformSource(ctx, originalTag.Name())
	require.NoError(t, err)
	originalIndexHash, err := index.Digest()
	require.NoError(t, err)
	require.Equal(t, originalIndexHash.String(), source.IndexLineage.Digest.String())
	first := map[string]*types.PatchResult{}
	for _, arch := range []string{"amd64", "386"} {
		first[arch] = patchOriginFixture(t, ctx, bk, repo+":original-"+arch, repo+":p1-"+arch, descriptors[arch].Platform, application)
		assertOriginFixture(t, ctx, first[arch], images[arch], application, false)
	}
	// Both patched platforms corroborate the common original index.
	pair := []types.PatchResult{*first["amd64"], *first["386"]}
	common := commonBaseIndexLineage(source, pair)
	require.NotNil(t, common)
	require.Equal(t, source.IndexLineage.Digest, common.Digest)
	outputRef, err := reference.ParseNormalizedNamed(repo + ":p1")
	require.NoError(t, err)
	outputTagged, ok := outputRef.(reference.NamedTagged)
	require.True(t, ok)
	require.NoError(t, createMultiPlatformManifest(ctx, outputTagged, pair, application, common))
	indexOut, err := remote.Index(originTestReference(t, repo+":p1"), remote.WithContext(ctx))
	require.NoError(t, err)
	indexManifest, err := indexOut.IndexManifest()
	require.NoError(t, err)
	for key, value := range common.Annotations() {
		require.Equal(t, value, indexManifest.Annotations[key])
	}
	for key, value := range application {
		require.Equal(t, value, indexManifest.Annotations[key])
	}
	// Docker schema 2 does not standardize annotations. Some exporters include
	// them anyway; assert format preservation and the portable config labels.
	t.Run("docker-schema2", func(t *testing.T) {
		output := repo + ":docker-schema2"
		bc, err := createBuildConfig(output, false, true, nil, application, "docker-schema2", "", false)
		require.NoError(t, err)
		bc.SolveOpt.Exports[0].Attrs["registry.insecure"] = "true"
		bc.SolveOpt.Exports[0].Attrs["oci-mediatypes"] = "false"
		_, err = bk.Build(ctx, bc.SolveOpt, "copa-schema2-origin-test", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
			def, err := first["amd64"].PatchedState.Marshal(ctx)
			if err != nil {
				return nil, err
			}
			result, err := c.Solve(ctx, gwclient.SolveRequest{Definition: def.ToPB(), Evaluate: true})
			if err != nil {
				return nil, err
			}
			result.AddMeta(exptypes.ExporterImageConfigKey, first["amd64"].ConfigData)
			addResultAnnotations(result, first["amd64"].PatchedDesc.Annotations)
			return result, nil
		}, nil)
		require.NoError(t, err)
		img, err := remote.Image(originTestReference(t, output), remote.WithContext(ctx))
		require.NoError(t, err)
		manifest, err := img.Manifest()
		require.NoError(t, err)
		require.Equal(t, v1types.DockerManifestSchema2, manifest.MediaType)
		cfg, err := img.ConfigFile()
		require.NoError(t, err)
		require.Equal(t, descriptors["amd64"].Digest.String(), cfg.Config.Labels[types.AnnotationPatchOriginDigest])
	})
	// Each second-generation invocation reads a real previously exported image.
	for _, scenario := range []string{"stable", "reused", "moved"} {
		t.Run(scenario, func(t *testing.T) {
			sourceTag := originTestReference(t, repo+":original-amd64")
			require.NoError(t, remote.Write(sourceTag, images["amd64"], remote.WithContext(ctx)))
			input := repo + ":p1-amd64"
			switch scenario {
			case "reused":
				p1, err := remote.Image(originTestReference(t, input), remote.WithContext(ctx))
				require.NoError(t, err)
				require.NoError(t, remote.Write(sourceTag, p1, remote.WithContext(ctx)))
				input = sourceTag.Name()
			case "moved":
				moved := originAnnotatedImage(t, images["amd64"], map[string]string{"fixture": "moved"})
				require.NoError(t, remote.Write(sourceTag, moved, remote.WithContext(ctx)))
			}
			second := patchOriginFixture(t, ctx, bk, input, repo+":p2-"+scenario+"-amd64", descriptors["amd64"].Platform, application)
			assertOriginFixture(t, ctx, second, images["amd64"], application, true)
		})
	}
	t.Run("immutable-index-source", func(t *testing.T) {
		input := repo + "@" + originalIndexHash.String()
		for _, arch := range []string{"amd64", "386"} {
			platform := descriptors[arch].Platform
			firstOutput := repo + ":p1-pinned-index-" + arch
			first := patchPublicOriginFixture(t, ctx, addr, input, firstOutput, platform)
			assertOriginFixture(t, ctx, first, images[arch], application, false)
			second := patchPublicOriginFixture(t, ctx, addr, firstOutput, repo+":p2-pinned-index-"+arch, platform)
			assertOriginFixture(t, ctx, second, images[arch], application, true)
		}
	})
	t.Run("recorded-index-locator", func(t *testing.T) {
		input := repo + "@" + originalIndexHash.String()
		for _, arch := range []string{"amd64", "386"} {
			// Existing P1 images can retain an index BaseImage while recording
			// the selected original child. Exercise that compatibility shape
			// independently of the reference captured by today's public P1 flow.
			img, err := remote.Image(originTestReference(t, repo+":p1-"+arch), remote.WithContext(ctx))
			require.NoError(t, err)
			config, err := img.ConfigFile()
			require.NoError(t, err)
			config.Config.Labels["BaseImage"] = input
			require.Equal(t, descriptors[arch].Digest.String(), config.Config.Labels[types.AnnotationPatchOriginDigest])
			img, err = mutate.ConfigFile(img, config)
			require.NoError(t, err)
			firstOutput := repo + ":p1-recorded-index-" + arch
			require.NoError(t, remote.Write(originTestReference(t, firstOutput), img, remote.WithContext(ctx)))
			second := patchPublicOriginFixture(t, ctx, addr, firstOutput, repo+":p2-recorded-index-"+arch, descriptors[arch].Platform)
			assertOriginFixture(t, ctx, second, images[arch], application, true)
		}
	})
	t.Run("second-generation-index", func(t *testing.T) {
		repatchSource, err := captureMultiPlatformSource(ctx, repo+":p1")
		require.NoError(t, err)
		require.Equal(t, source.IndexLineage, repatchSource.IndexLineage)
		var secondPair []types.PatchResult
		for _, arch := range []string{"amd64", "386"} {
			input, err := platformSourceReference(repatchSource.Current, descriptors[arch].Platform)
			require.NoError(t, err)
			second := patchOriginFixture(t, ctx, bk, input, repo+":p2-index-"+arch, descriptors[arch].Platform, application)
			assertOriginFixture(t, ctx, second, images[arch], application, true)
			secondPair = append(secondPair, *second)
		}
		secondOrigin := commonBaseIndexLineage(repatchSource, secondPair)
		require.Equal(t, common, secondOrigin)
		ref, err := reference.ParseNormalizedNamed(repo + ":p2-index")
		require.NoError(t, err)
		tagged, ok := ref.(reference.NamedTagged)
		require.True(t, ok)
		require.NoError(t, createMultiPlatformManifest(ctx, tagged, secondPair, application, secondOrigin))
		result, err := remote.Index(originTestReference(t, tagged.String()), remote.WithContext(ctx))
		require.NoError(t, err)
		manifest, err := result.IndexManifest()
		require.NoError(t, err)
		for key, value := range common.Annotations() {
			require.Equal(t, value, manifest.Annotations[key])
		}
		for key, value := range application {
			require.Equal(t, value, manifest.Annotations[key])
		}
	})
	t.Run("frontend", func(t *testing.T) {
		// Earlier tag-move scenarios deliberately changed this mutable locator.
		require.NoError(t, remote.Write(originTestReference(t, repo+":original-amd64"), images["amd64"], remote.WithContext(ctx)))
		for _, scenario := range []struct{ name, input, platform string }{
			{"default", repo + ":original-amd64", ""},
			{"amd64-index", repo + "@" + originalIndexHash.String(), "linux/amd64"},
			{"386-index", repo + "@" + originalIndexHash.String(), "linux/386"},
		} {
			t.Run(scenario.name, func(t *testing.T) {
				arch := originAMD64
				if scenario.platform == "linux/386" {
					arch = "386"
				}
				input := scenario.input
				expectedOrigin := descriptors[arch].Digest.String()
				if scenario.platform != "" {
					expectedOrigin = originalIndexHash.String()
				}
				var previousLayers []v1.Descriptor
				for generation := 1; generation <= 3; generation++ {
					output := fmt.Sprintf("%s:frontend-%s-p%d", repo, scenario.name, generation)
					solveOpt := client.SolveOpt{
						FrontendAttrs: map[string]string{"image": input},
						Exports: []client.ExportEntry{{Type: client.ExporterImage, Attrs: map[string]string{
							"name": output, "push": "true", "registry.insecure": "true", "oci-mediatypes": "true",
						}}},
					}
					if scenario.platform != "" {
						solveOpt.FrontendAttrs["platform"] = scenario.platform
					}
					if generation == 2 {
						reportPath := originTestReport(t, arch)
						mount, err := fsutil.NewFS(filepath.Dir(reportPath))
						require.NoError(t, err)
						solveOpt.LocalMounts = map[string]fsutil.FS{"report": mount}
						solveOpt.FrontendAttrs["report"] = filepath.Base(reportPath)
					}
					_, err := bk.Build(ctx, solveOpt, "copa-origin-frontend-test", frontend.Build, nil)
					require.NoError(t, err)
					img, err := remote.Image(originTestReference(t, output), remote.WithContext(ctx), remote.WithPlatform(v1.Platform{OS: "linux", Architecture: arch}))
					require.NoError(t, err)
					mfst, err := img.Manifest()
					require.NoError(t, err)
					cfg, err := img.ConfigFile()
					require.NoError(t, err)
					for _, surface := range []map[string]string{mfst.Annotations, cfg.Config.Labels} {
						require.Equal(t, types.PatchOriginImage, surface[types.AnnotationPatchOriginKind])
						require.Equal(t, expectedOrigin, surface[types.AnnotationPatchOriginDigest])
					}
					for key, value := range application {
						require.Equal(t, value, cfg.Config.Labels[key])
					}
					originalManifest, err := images[arch].Manifest()
					require.NoError(t, err)
					for i, layer := range originalManifest.Layers {
						require.Equal(t, layer.Digest, mfst.Layers[i].Digest)
					}
					if generation == 2 {
						// BuildKit can retain an empty tar layer; count actual
						// filesystem changes to prove the previous patch was replaced.
						layers, err := img.Layers()
						require.NoError(t, err)
						changed := 0
						for _, layer := range layers[len(originalManifest.Layers):] {
							stream, err := layer.Uncompressed()
							require.NoError(t, err)
							_, err = tar.NewReader(stream).Next()
							require.True(t, err == nil || err == io.EOF)
							if err == nil {
								changed++
							}
							require.NoError(t, stream.Close())
						}
						require.Equal(t, 1, changed, "one replacement patch with filesystem changes")
					}
					if generation == 3 {
						require.Equal(t, previousLayers, mfst.Layers, "no-op re-patch preserves the supplied layers")
					}
					previousLayers = mfst.Layers
					input = output
				}
				cliOutput := repo + ":frontend-to-cli-" + scenario.name
				cli := patchPublicOriginFixture(t, ctx, addr, input, cliOutput, descriptors[arch].Platform)
				cfgImage, err := remote.Image(originTestReference(t, cliOutput), remote.WithContext(ctx))
				require.NoError(t, err)
				cfg, err := cfgImage.ConfigFile()
				require.NoError(t, err)
				require.Equal(t, expectedOrigin, cfg.Config.Labels[types.AnnotationPatchOriginDigest])
				require.Equal(t, expectedOrigin, cli.PatchedDesc.Annotations[types.AnnotationPatchOriginDigest])
				mfst, err := cfgImage.Manifest()
				require.NoError(t, err)
				originalManifest, err := images[arch].Manifest()
				require.NoError(t, err)
				require.Len(t, mfst.Layers, len(originalManifest.Layers)+1)
				for key, value := range application {
					require.Equal(t, value, cfg.Config.Labels[key])
				}
			})
		}
	})
	testOriginSnapshotFollowups(t, ctx, addr, repo, images, application)
	testAuthenticatedIndexOrigin(t, ctx, bk, repo, application)
	testSourceAnnotationFollowups(t, ctx, addr, repo, images, application)
	t.Run("partial-repatch-index", func(t *testing.T) {
		for _, recorded := range []bool{true, false} {
			inputIndex := indexOut
			if !recorded {
				var children []mutate.IndexAddendum
				for _, desc := range indexManifest.Manifests {
					img, err := indexOut.Image(desc.Digest)
					require.NoError(t, err)
					children = append(children, mutate.IndexAddendum{Add: img, Descriptor: desc})
				}
				inputIndex = mutate.IndexMediaType(mutate.AppendManifests(empty.Index, children...), v1types.OCIImageIndex)
			}
			inputManifest, err := inputIndex.IndexManifest()
			require.NoError(t, err)
			input := fmt.Sprintf("%s:partial-input-%t", repo, recorded)
			output := fmt.Sprintf("partial-output-%t", recorded)
			require.NoError(t, remote.WriteIndex(originTestReference(t, input), inputIndex, remote.WithContext(ctx)))
			require.NoError(t, Patch(ctx, &types.Options{
				Image: input, Push: true, PatchedTag: output, BkAddr: addr,
				PkgTypes: "os", Platforms: []string{"linux/amd64"}, Progress: "quiet", Timeout: time.Minute,
			}))
			result, err := remote.Index(originTestReference(t, repo+":"+output), remote.WithContext(ctx))
			require.NoError(t, err)
			mfst, err := result.IndexManifest()
			require.NoError(t, err)
			require.Empty(t, mfst.Annotations[types.AnnotationPatchOriginDigest], "preserved patched siblings offer only unverified ancestry")
			for _, desc := range mfst.Manifests {
				if desc.Platform.Architecture == "386" {
					var original v1.Descriptor
					for _, prior := range inputManifest.Manifests {
						if prior.Platform.Architecture == "386" {
							original = prior
						}
					}
					require.Equal(t, original, desc, "preserved patched child descriptor must be unchanged")
					img, err := result.Image(desc.Digest)
					require.NoError(t, err)
					verifyOriginBlobs(t, img)
				}
			}
		}
	})
	t.Run("inconsistent-recorded-index", func(t *testing.T) {
		for _, surface := range []string{"descriptor", originManifestSurface, originConfigSurface} {
			for _, mismatch := range []string{"repository", "digest"} {
				t.Run(surface+"-"+mismatch, func(t *testing.T) {
					child, err := remote.Image(originTestReference(t, repo+":p1-amd64"), remote.WithContext(ctx))
					require.NoError(t, err)
					claims := maps.Clone(first["amd64"].PatchedDesc.Annotations)
					if mismatch == "repository" {
						claims[types.AnnotationPatchOriginName] = repo + "-different:original"
					} else {
						claims[types.AnnotationPatchOriginDigest] = descriptors["386"].Digest.String()
					}
					descriptorAnnotations := maps.Clone(first["amd64"].PatchedDesc.Annotations)
					switch surface {
					case "descriptor":
						descriptorAnnotations = claims
					case originManifestSurface:
						child = originAnnotatedImage(t, child, claims)
					case originConfigSurface:
						cfg, err := child.ConfigFile()
						require.NoError(t, err)
						maps.Copy(cfg.Config.Labels, claims)
						child, err = mutate.ConfigFile(child, cfg)
						require.NoError(t, err)
					}
					other, err := remote.Image(originTestReference(t, repo+":p1-386"), remote.WithContext(ctx))
					require.NoError(t, err)
					for _, count := range []int{1, 2} {
						children := []mutate.IndexAddendum{{Add: child, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}, Annotations: descriptorAnnotations}}}
						if count == 2 {
							children = append(children, mutate.IndexAddendum{Add: other, Descriptor: v1.Descriptor{
								Platform: &v1.Platform{OS: "linux", Architecture: "386"}, Annotations: first["386"].PatchedDesc.Annotations,
							}})
						}
						bad := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, children...), v1types.OCIImageIndex)
						annotated, ok := mutate.Annotations(bad, common.Annotations()).(v1.ImageIndex)
						require.True(t, ok)
						bad = annotated
						input := fmt.Sprintf("%s:inconsistent-%s-%s-%d", repo, surface, mismatch, count)
						require.NoError(t, remote.WriteIndex(originTestReference(t, input), bad, remote.WithContext(ctx)))
						tag := fmt.Sprintf("rejected-%s-%s-%d", surface, mismatch, count)
						err = Patch(ctx, &types.Options{Image: input, Push: true, PatchedTag: tag, BkAddr: addr, PkgTypes: "os", IgnoreError: true, Progress: "quiet", Timeout: time.Minute})
						require.ErrorIs(t, err, errRecordedIndexOrigin)
						for _, suffix := range []string{"", "-amd64", "-386"} {
							_, err := remote.Get(originTestReference(t, repo+":"+tag+suffix), remote.WithContext(ctx))
							require.Error(t, err, "inconsistent origin must fail before any output")
						}
					}
				})
			}
		}
	})
	t.Run("missing-original-index", func(t *testing.T) {
		input := repo + ":missing-original-index"
		require.NoError(t, remote.WriteIndex(originTestReference(t, input), indexOut, remote.WithContext(ctx)))
		singleInput := repo + ":missing-original-index-single"
		singleIndex := mutate.RemoveManifests(indexOut, func(d v1.Descriptor) bool {
			return d.Platform == nil || d.Platform.Architecture != "amd64"
		})
		require.NoError(t, remote.WriteIndex(originTestReference(t, singleInput), singleIndex, remote.WithContext(ctx)))
		originalRef := originTestReference(t, repo+"@"+originalIndexHash.String())
		require.NoError(t, remote.Delete(originalRef, remote.WithContext(ctx)))
		defer func() {
			// The tag still exists after deletion; restore the missing digest directly.
			require.NoError(t, remote.WriteIndex(originalRef, index, remote.WithContext(ctx)))
			_, err := remote.Get(originalRef, remote.WithContext(ctx))
			require.NoError(t, err)
		}()
		_, err := remote.Get(originalRef, remote.WithContext(ctx))
		require.Error(t, err, "the recorded original index must be unavailable")
		// P1 children and each original A manifest remain available. Their
		// successful resolution must not excuse the missing recorded index.
		for _, child := range indexManifest.Manifests {
			img, err := remote.Image(originTestReference(t, repo+"@"+child.Digest.String()), remote.WithContext(ctx))
			require.NoError(t, err)
			cfg, err := img.ConfigFile()
			require.NoError(t, err)
			_, err = remote.Get(originTestReference(t, repo+"@"+cfg.Config.Labels[types.AnnotationPatchOriginDigest]), remote.WithContext(ctx))
			require.NoError(t, err)
		}
		for _, input := range []string{input, singleInput} {
			err = Patch(ctx, &types.Options{
				Image: input, Push: true, PatchedTag: "rejected-index", BkAddr: addr,
				PkgTypes: "os", IgnoreError: true, Progress: "quiet", Timeout: time.Minute,
			})
			require.ErrorIs(t, err, errRecordedIndexOrigin)
			require.ErrorContains(t, err, "restore the original index")
			for _, tag := range []string{"rejected-index", "rejected-index-amd64", "rejected-index-386"} {
				_, err := remote.Get(originTestReference(t, repo+":"+tag), remote.WithContext(ctx))
				require.Error(t, err, "rejected recovery must not produce output %s", tag)
			}
		}
	})
	t.Run("missing-original", func(t *testing.T) {
		p1, err := remote.Image(originTestReference(t, repo+":p1-amd64"), remote.WithContext(ctx))
		require.NoError(t, err)
		cfg, err := p1.ConfigFile()
		require.NoError(t, err)
		cfg.Config.Labels[types.AnnotationPatchOriginDigest] = digest.FromString("unavailable original").String()
		broken, err := mutate.ConfigFile(p1, cfg)
		require.NoError(t, err)
		ref := repo + ":missing-original"
		require.NoError(t, remote.Write(originTestReference(t, ref), broken, remote.WithContext(ctx)))
		var recoveryErr error
		_, err = bk.Build(ctx, client.SolveOpt{}, "copa-missing-origin-test", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
			_, recoveryErr = buildkit.InitializeBuildkitConfig(ctx, c, ref, descriptors["amd64"].Platform)
			return &gwclient.Result{}, recoveryErr
		}, nil)
		require.Error(t, err)
		require.ErrorContains(t, recoveryErr, "restore the original image")
	})
	// Export the same patched state with an untouched 386 platform and its
	// attestation after the mutable source index tag has moved.
	preservedRef, err := reference.ParseNormalizedNamed(originalTag.Name())
	require.NoError(t, err)
	pinned, err := immutableCurrentIndexReference(source)
	require.NoError(t, err)
	sourceManifest, err := index.IndexManifest()
	require.NoError(t, err)
	preservedDesc := source.Current.Index.Manifests[1]
	mixed := []types.PatchResult{*first["amd64"], {OriginalRef: preservedRef, PatchedRef: preservedRef, PatchedDesc: &preservedDesc}}
	mixedOrigin := commonBaseIndexLineage(source, mixed)
	require.NotNil(t, mixedOrigin)
	require.NoError(t, remote.WriteIndex(originalTag, mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: images["amd64"]}), remote.WithContext(ctx)))
	dir := filepath.Join(t.TempDir(), "mixed")
	annotations := multiPlatformIndexAnnotations(outputTagged, application, mixedOrigin, time.Unix(0, 0))
	layoutPlatforms := []types.PatchPlatform{
		{Platform: specs.Platform{OS: "linux", Architecture: "amd64"}},
		{Platform: specs.Platform{OS: "linux", Architecture: "386"}, ShouldPreserve: true},
	}
	exportOptions := buildkit.OCILayoutExportOptions{IndexAnnotations: annotations, PreservedSourceRef: pinned}
	require.NoError(t, buildkit.CreateOCILayoutFromResultsWithContext(ctx, dir, mixed, layoutPlatforms, exportOptions))
	lp, err := layout.FromPath(dir)
	require.NoError(t, err)
	resultIndex, err := lp.ImageIndex()
	require.NoError(t, err)
	resultManifest, err := resultIndex.IndexManifest()
	require.NoError(t, err)
	require.Equal(t, annotations, resultManifest.Annotations)
	require.Len(t, resultManifest.Manifests, 3)
	for _, expected := range sourceManifest.Manifests[1:] {
		found := false
		for _, actual := range resultManifest.Manifests {
			if actual.Digest == expected.Digest {
				require.Equal(t, expected, actual)
				found = true
			}
		}
		require.True(t, found, "preserved descriptor %s", expected.Digest)
		copied, err := resultIndex.Image(expected.Digest)
		require.NoError(t, err)
		verifyOriginBlobs(t, copied)
	}
	patchedLayout, err := resultIndex.Image(resultManifest.Manifests[0].Digest)
	require.NoError(t, err)
	rawManifest, err := patchedLayout.Manifest()
	require.NoError(t, err)
	for key, value := range first["amd64"].PatchedDesc.Annotations {
		require.Equal(t, value, rawManifest.Annotations[key], "layout/registry annotation %s", key)
	}
	verifyOriginBlobs(t, patchedLayout)
	// A local daemon image remains authoritative when a same-name registry tag moves.
	t.Run("daemon-source", func(t *testing.T) {
		localTag := repo + ":daemon-original"
		require.NoError(t, remote.Write(originTestReference(t, localTag), images["amd64"], remote.WithContext(ctx)))
		command := exec.CommandContext(ctx, "docker", "pull", localTag)
		output, err := command.CombinedOutput()
		require.NoError(t, err, string(output))
		t.Cleanup(func() {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			command := exec.CommandContext(cleanupCtx, "docker", "image", "rm", localTag)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Logf("remove task image: %v: %s", err, output)
			}
		})
		moved := originAnnotatedImage(t, images["amd64"], map[string]string{"fixture": "different-remote-source"})
		require.NoError(t, remote.Write(originTestReference(t, localTag), moved, remote.WithContext(ctx)))
		captured, err := buildkit.ResolveImageSource(ctx, localTag)
		require.NoError(t, err)
		require.Equal(t, descriptors["amd64"].Digest, captured.Descriptor.Digest)
		daemonBuilder, err := buildkit.NewClient(ctx, buildkit.Opts{Addr: "docker://"})
		require.NoError(t, err)
		defer daemonBuilder.Close()
		localFirst := patchOriginFixture(t, ctx, daemonBuilder, localTag, repo+":daemon-p1-amd64", descriptors["amd64"].Platform, application)
		assertOriginFixture(t, ctx, localFirst, images["amd64"], application, false)
		localSecond := patchOriginFixture(t, ctx, daemonBuilder, repo+":daemon-p1-amd64", repo+":daemon-p2-amd64", descriptors["amd64"].Platform, application)
		assertOriginFixture(t, ctx, localSecond, images["amd64"], application, true)
	})
	if !t.Failed() {
		t.Logf("Verified original index %s across two platforms, re-patch, preservation, and exports", originalIndexHash)
	}
}

func originTestReference(t *testing.T, value string) name.Reference {
	t.Helper()
	ref, err := name.ParseReference(value)
	require.NoError(t, err)
	return ref
}

func patchPublicOriginFixture(t *testing.T, ctx context.Context, addr, input, output string, platform *specs.Platform) *types.PatchResult {
	t.Helper()
	reportPath := originTestReport(t, platform.Architecture)
	outputRef, err := name.NewTag(output)
	require.NoError(t, err)
	require.NoError(t, Patch(ctx, &types.Options{
		Image: input, Report: reportPath, Scanner: "trivy", Push: true, PatchedTag: outputRef.TagStr(), BkAddr: addr,
		PkgTypes: "os", Progress: "quiet", Timeout: 5 * time.Minute,
	}))
	desc, err := remote.Get(originTestReference(t, output), remote.WithContext(ctx))
	require.NoError(t, err)
	img, err := desc.Image()
	require.NoError(t, err)
	manifest, err := img.Manifest()
	require.NoError(t, err)
	originalRef, err := reference.ParseNormalizedNamed(input)
	require.NoError(t, err)
	patchedRef, err := reference.ParseNormalizedNamed(output)
	require.NoError(t, err)
	return &types.PatchResult{OriginalRef: originalRef, PatchedRef: patchedRef, PatchedDesc: &specs.Descriptor{
		MediaType: string(desc.MediaType), Digest: digest.Digest(desc.Digest.String()), Size: desc.Size,
		Platform: platform, Annotations: manifest.Annotations,
	}}
}

func patchOriginFixture(t *testing.T, ctx context.Context, bk *client.Client, input, output string, original *specs.Platform, annotations map[string]string) *types.PatchResult {
	t.Helper()
	bc, err := createBuildConfig(output, true, true, nil, annotations, "p1", "", false)
	require.NoError(t, err)
	bc.SolveOpt.Exports[0].Attrs["registry.insecure"] = "true"
	var core *Result
	_, err = bk.Build(ctx, bc.SolveOpt, "copa-origin-test", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		var err error
		core, err = ExecutePatchCore(&Context{Context: ctx, Client: c}, &Options{
			ImageName: input, TargetPlatform: &types.PatchPlatform{Platform: *original}, WorkingFolder: t.TempDir(),
			Updates: &unversioned.UpdateManifest{
				Metadata:  unversioned.Metadata{OS: unversioned.OS{Type: "alpine", Version: "3.20.0"}, Config: unversioned.Config{Arch: original.Architecture}},
				OSUpdates: unversioned.UpdatePackages{{Name: "busybox", InstalledVersion: "1.36.1-r29", FixedVersion: "1.36.1-r29"}},
			},
		})
		if err != nil {
			return nil, err
		}
		return core.Result, nil
	}, nil)
	require.NoError(t, err)
	desc, err := remote.Get(originTestReference(t, output), remote.WithContext(ctx))
	require.NoError(t, err)
	originalRef, err := reference.ParseNormalizedNamed(input)
	require.NoError(t, err)
	patchedRef, err := reference.ParseNormalizedNamed(output)
	require.NoError(t, err)
	patchedDesc := &specs.Descriptor{MediaType: string(desc.MediaType), Digest: digest.Digest(desc.Digest.String()), Size: desc.Size, Platform: original, Annotations: maps.Clone(annotations)}
	maps.Copy(patchedDesc.Annotations, core.Annotations)
	return &types.PatchResult{OriginalRef: originalRef, PatchedRef: patchedRef, PatchedDesc: patchedDesc, PatchedState: core.PatchedState, ConfigData: core.ConfigData}
}

func assertOriginFixture(t *testing.T, ctx context.Context, result *types.PatchResult, original v1.Image, application map[string]string, repatch bool) {
	t.Helper()
	patched, err := remote.Image(originTestReference(t, result.PatchedRef.String()), remote.WithContext(ctx))
	require.NoError(t, err)
	manifest, err := patched.Manifest()
	require.NoError(t, err)
	cfg, err := patched.ConfigFile()
	require.NoError(t, err)
	originHash, err := original.Digest()
	require.NoError(t, err)
	for _, surface := range []map[string]string{manifest.Annotations, cfg.Config.Labels, result.PatchedDesc.Annotations} {
		require.Equal(t, types.PatchOriginImage, surface[types.AnnotationPatchOriginKind])
		require.Equal(t, originHash.String(), surface[types.AnnotationPatchOriginDigest])
		for key, value := range application {
			require.Equal(t, value, surface[key])
		}
	}
	baseManifest, err := original.Manifest()
	require.NoError(t, err)
	if repatch {
		require.Len(t, manifest.Layers, len(baseManifest.Layers)+1, "previous patch layers are replaced by one squashed layer")
	} else {
		require.Greater(t, len(manifest.Layers), len(baseManifest.Layers), "first patch installs updates")
	}
	for i := range baseManifest.Layers {
		require.Equal(t, baseManifest.Layers[i].Digest, manifest.Layers[i].Digest)
	}
	t.Logf("%s points directly to %s with %d original + %d patch layers", result.PatchedRef, originHash, len(baseManifest.Layers), len(manifest.Layers)-len(baseManifest.Layers))
}

func verifyOriginBlobs(t *testing.T, img v1.Image) {
	t.Helper()
	raw, err := img.RawManifest()
	require.NoError(t, err)
	h, err := img.Digest()
	require.NoError(t, err)
	require.Equal(t, h.String(), digest.FromBytes(raw).String())
	cfg, err := img.RawConfigFile()
	require.NoError(t, err)
	ch, err := img.ConfigName()
	require.NoError(t, err)
	require.Equal(t, ch.String(), digest.FromBytes(cfg).String())
	layers, err := img.Layers()
	require.NoError(t, err)
	for _, layer := range layers {
		h, err := layer.Digest()
		require.NoError(t, err)
		r, err := layer.Compressed()
		require.NoError(t, err)
		data, err := io.ReadAll(r)
		require.NoError(t, err)
		require.NoError(t, r.Close())
		require.Equal(t, h.String(), digest.FromBytes(data).String())
	}
	var document map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &document))
}

func originAnnotatedImage(t *testing.T, img v1.Image, annotations map[string]string) v1.Image {
	t.Helper()
	annotated, ok := mutate.Annotations(img, annotations).(v1.Image)
	require.True(t, ok)
	return annotated
}

func originTestReport(t *testing.T, arch string) string {
	t.Helper()
	report := fmt.Sprintf(`{"SchemaVersion":2,"ArtifactType":"container_image",
 "Metadata":{"OS":{"Family":"alpine","Name":"3.20.0"},"ImageConfig":{"architecture":%q}},
 "Results":[{"Class":"os-pkgs","Type":"alpine","Vulnerabilities":[
 {"VulnerabilityID":"CVE-2023-42363","PkgName":"busybox","InstalledVersion":"1.36.1-r29","FixedVersion":"1.36.1-r29"}]}]}`, arch)
	reportPath := filepath.Join(t.TempDir(), "report.json")
	require.NoError(t, os.WriteFile(reportPath, []byte(report), 0o600))
	return reportPath
}
