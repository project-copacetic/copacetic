package patch

import (
	"context"
	"fmt"
	"io"
	stdlog "log"
	"maps"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestOriginContract checks the patch-origin contract through the public Patch
// entry point with a real BuildKit and a disposable registry. CI runs it with
// COPA_ORIGIN_BUILDKIT_ADDR naming a host-networked BuildKit. The --oci-dir
// case loads patched platforms into the Docker daemon from DOCKER_HOST, and its
// layout export uses the buildx builder named by BUILDX_BUILDER.
//
// For each BaseImage locator spelling, through single- and multi-platform
// patching, it asserts that P1 records the exact original digest of A, that
// re-patching P1 records A again and replaces P1's patch layer, and that
// BaseImage keeps the supplied locator. It also compares --oci-dir output with
// registry output, and checks that a missing original fails without output.
func TestOriginContract(t *testing.T) {
	addr := os.Getenv("COPA_ORIGIN_BUILDKIT_ADDR")
	if addr == "" {
		t.Skip("set COPA_ORIGIN_BUILDKIT_ADDR to run the origin contract against a real BuildKit")
	}
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
	repo := listener.Addr().String() + "/copa-origin-contract"

	// A: an application image whose own base metadata names B.
	application := map[string]string{
		specs.AnnotationBaseImageName:   "example.com/application-base:stable",
		specs.AnnotationBaseImageDigest: "sha256:" + fmt.Sprintf("%064d", 1),
	}
	arches := []string{originAMD64, "386"}
	originals := map[string]v1.Image{}
	children := map[string]string{}
	var addenda []mutate.IndexAddendum
	for _, arch := range arches {
		img, err := remote.Image(originTestReference(t, "alpine:3.20.0"), remote.WithContext(ctx), remote.WithPlatform(v1.Platform{OS: LINUX, Architecture: arch}))
		require.NoError(t, err)
		cfg, err := img.ConfigFile()
		require.NoError(t, err)
		cfg = cfg.DeepCopy()
		cfg.Config.Labels = maps.Clone(application)
		img, err = mutate.ConfigFile(img, cfg)
		require.NoError(t, err)
		img = originAnnotatedImage(t, mutate.MediaType(img, v1types.OCIManifestSchema1), application)
		hash, err := img.Digest()
		require.NoError(t, err)
		originals[arch], children[arch] = img, hash.String()
		addenda = append(addenda, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: LINUX, Architecture: arch}}})
	}
	index := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, addenda...), v1types.OCIImageIndex)
	index, ok := mutate.Annotations(index, application).(v1.ImageIndex)
	require.True(t, ok)
	indexHash, err := index.Digest()
	require.NoError(t, err)
	for _, tag := range []string{"original", "latest"} {
		require.NoError(t, remote.WriteIndex(originTestReference(t, repo+":"+tag), index, remote.WithContext(ctx)))
	}
	reports := t.TempDir()
	for _, arch := range arches {
		data, err := os.ReadFile(originTestReport(t, arch))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(reports, arch+".json"), data, 0o600))
	}
	patch := func(input, tag, report string, extra func(*types.Options)) error {
		opts := &types.Options{
			Image: input, Report: report, Scanner: "trivy", Push: true, PatchedTag: tag, BkAddr: addr,
			PkgTypes: "os", Progress: "quiet", Timeout: 5 * time.Minute,
		}
		if extra != nil {
			extra(opts)
		}
		return Patch(ctx, opts)
	}

	t.Run("report-directory-single-manifest", func(t *testing.T) {
		input := repo + ":single-manifest"
		require.NoError(t, remote.Write(originTestReference(t, input), originals[originAMD64], remote.WithContext(ctx)))
		require.NoError(t, patch(input, "single-manifest-directory-p1", reports, nil))
		result, err := remote.Index(originTestReference(t, repo+":single-manifest-directory-p1"), remote.WithContext(ctx))
		require.NoError(t, err)
		manifest, err := result.IndexManifest()
		require.NoError(t, err)
		require.Len(t, manifest.Manifests, 1)
		require.NotContains(t, manifest.Annotations, types.AnnotationPatchOriginDigest, "an image manifest is not an original index")
		assertContractOrigin(t, contractPlatformImage(t, result, manifest, originAMD64), children[originAMD64], application)
	})

	t.Run("source-policy-selected-input", func(t *testing.T) {
		input := repo + ":policy-input"
		cfg, err := originals[originAMD64].ConfigFile()
		require.NoError(t, err)
		cfg = cfg.DeepCopy()
		cfg.Config.Labels["com.example.unapproved"] = attrValueTrue
		unapproved, err := mutate.ConfigFile(originals[originAMD64], cfg)
		require.NoError(t, err)
		require.NoError(t, remote.Write(originTestReference(t, input), unapproved, remote.WithContext(ctx)))
		policy := fmt.Sprintf(`{"rules":[{"action":"CONVERT","selector":{"identifier":%q},"updates":{"identifier":%q}}]}`,
			"docker-image://"+input, "docker-image://"+repo+"@"+children[originAMD64])
		policyPath := filepath.Join(t.TempDir(), "source-policy.json")
		require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0o600))
		t.Setenv("EXPERIMENTAL_BUILDKIT_SOURCE_POLICY", policyPath)
		require.NoError(t, patch(input, "policy-output", originTestReport(t, originAMD64), nil))
		result := contractImage(t, ctx, repo+":policy-output")
		assertContractOrigin(t, result, children[originAMD64], application)
		require.NotContains(t, contractLabels(t, result), "com.example.unapproved")
		require.Equal(t, repo+"@"+children[originAMD64], contractLabels(t, result)["BaseImage"])
	})

	t.Run("preserved-windows-versions", func(t *testing.T) {
		addenda := []mutate.IndexAddendum{{Add: originals[originAMD64], Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: LINUX, Architecture: originAMD64}}}}
		for _, version := range []string{"10.0.20348.0", "10.0.26100.0"} {
			windows, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{OS: "windows", Architecture: originAMD64, OSVersion: version})
			require.NoError(t, err)
			addenda = append(addenda, mutate.IndexAddendum{Add: windows, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "windows", Architecture: originAMD64, OSVersion: version}}})
		}
		input := repo + ":windows-source"
		index := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, addenda...), v1types.OCIImageIndex)
		require.NoError(t, remote.WriteIndex(originTestReference(t, input), index, remote.WithContext(ctx)))
		require.NoError(t, patch(input, "windows-preserved", reports, nil))
		result, err := remote.Index(originTestReference(t, repo+":windows-preserved"), remote.WithContext(ctx))
		require.NoError(t, err)
		manifest, err := result.IndexManifest()
		require.NoError(t, err)
		require.Len(t, manifest.Manifests, 3)
		original, err := index.IndexManifest()
		require.NoError(t, err)
		for _, expected := range original.Manifests[1:] {
			require.Contains(t, manifest.Manifests, expected, "preserve each exact Windows descriptor")
		}
	})

	locators := []struct{ name, input string }{
		{"repository", repo},
		{"tag", repo + ":original"},
		{"tag-and-index", repo + ":original@" + indexHash.String()},
	}
	for _, locator := range locators {
		named, err := reference.ParseNormalizedNamed(locator.input)
		require.NoError(t, err)
		supplied := named.String()

		t.Run("single-platform/"+locator.name, func(t *testing.T) {
			p1 := "single-" + locator.name + "-p1"
			require.NoError(t, patch(locator.input, p1, originTestReport(t, originAMD64), nil))
			first := contractImage(t, ctx, repo+":"+p1)
			assertContractOrigin(t, first, children[originAMD64], application)
			require.Equal(t, supplied, contractLabels(t, first)["BaseImage"], "BaseImage keeps the supplied locator")
			assertContractLayers(t, first, originals[originAMD64], false)

			p2 := "single-" + locator.name + "-p2"
			require.NoError(t, patch(repo+":"+p1, p2, originTestReport(t, originAMD64), nil))
			second := contractImage(t, ctx, repo+":"+p2)
			assertContractOrigin(t, second, children[originAMD64], application)
			require.Equal(t, supplied, contractLabels(t, second)["BaseImage"], "a re-patch keeps the recorded locator")
			assertContractLayers(t, second, originals[originAMD64], true)
		})

		t.Run("multi-platform/"+locator.name, func(t *testing.T) {
			p1 := "multi-" + locator.name + "-p1"
			require.NoError(t, patch(locator.input, p1, reports, nil))
			p2 := "multi-" + locator.name + "-p2"
			require.NoError(t, patch(repo+":"+p1, p2, reports, nil))
			for generation, tag := range []string{p1, p2} {
				result, err := remote.Index(originTestReference(t, repo+":"+tag), remote.WithContext(ctx))
				require.NoError(t, err)
				manifest, err := result.IndexManifest()
				require.NoError(t, err)
				require.Equal(t, types.PatchOriginImage, manifest.Annotations[types.AnnotationPatchOriginKind])
				require.Equal(t, indexHash.String(), manifest.Annotations[types.AnnotationPatchOriginDigest], "the index records the original index")
				seen := 0
				for _, desc := range manifest.Manifests {
					if desc.Platform == nil || desc.Platform.OS != LINUX {
						continue
					}
					seen++
					arch := desc.Platform.Architecture
					require.Equal(t, children[arch], desc.Annotations[types.AnnotationPatchOriginDigest])
					img, err := result.Image(desc.Digest)
					require.NoError(t, err)
					assertContractOrigin(t, img, children[arch], application)
					require.Equal(t, supplied, contractLabels(t, img)["BaseImage"])
					assertContractLayers(t, img, originals[arch], generation == 1)
				}
				require.Equal(t, len(arches), seen)
			}
		})
	}

	t.Run("gateway-recorded-index", func(t *testing.T) {
		bk, err := buildkit.NewClient(ctx, buildkit.Opts{Addr: addr})
		require.NoError(t, err)
		defer bk.Close()
		var native bool
		_, err = bk.Build(ctx, authenticatedSolveOpt(), copaProduct, func(_ context.Context, c gwclient.Client) (*gwclient.Result, error) {
			buildOpts := c.BuildOpts()
			native = buildOpts.LLBCaps.Supports(pb.CapSourceImageBlob) == nil
			return gwclient.NewResult(), nil
		}, nil)
		require.NoError(t, err)
		if !native {
			t.Skip("gateway-only index metadata requires BuildKit image-blob sources")
		}
		require.NoError(t, patch(repo+":original", "gateway-recovery-input", reports, nil))
		transport := remote.DefaultTransport
		t.Cleanup(func() { remote.DefaultTransport = transport })
		blocked := &sourceSessionTransport{
			RoundTripper: transport,
			inputPath:    "/v2/" + strings.SplitN(repo, "/", 2)[1] + "/manifests/" + indexHash.String(),
		}
		remote.DefaultTransport = blocked
		// Current input remains host-readable; only the original index needs
		// the worker session. Recovery must reuse the captured current snapshot.
		_, err = remote.Get(originTestReference(t, repo+":gateway-recovery-input"), remote.WithContext(ctx))
		require.NoError(t, err)
		require.NoError(t, patch(repo+":gateway-recovery-input", "gateway-recovery-output", originTestReport(t, originAMD64), nil))
		require.Positive(t, blocked.denied.Load())
		assertContractOrigin(t, contractImage(t, ctx, repo+":gateway-recovery-output"), children[originAMD64], application)
	})

	t.Run("oci-dir-parity", func(t *testing.T) {
		require.NoError(t, patch(repo+":original", "registry-output", reports, nil))
		registryIndex, err := remote.Index(originTestReference(t, repo+":registry-output"), remote.WithContext(ctx))
		require.NoError(t, err)
		dir := filepath.Join(t.TempDir(), "layout")
		t.Cleanup(func() {
			for _, arch := range arches {
				removeContractImage(t, repo+":layout-output-"+arch)
			}
		})
		require.NoError(t, patch(repo+":original", "layout-output", reports, func(opts *types.Options) {
			opts.Push, opts.OCIDir = false, dir
		}))
		path, err := layout.FromPath(dir)
		require.NoError(t, err)
		layoutIndex, err := path.ImageIndex()
		require.NoError(t, err)
		registryManifest, err := registryIndex.IndexManifest()
		require.NoError(t, err)
		layoutManifest, err := layoutIndex.IndexManifest()
		require.NoError(t, err)
		require.Equal(t, originAnnotations(registryManifest.Annotations), originAnnotations(layoutManifest.Annotations))
		require.Equal(t, indexHash.String(), layoutManifest.Annotations[types.AnnotationPatchOriginDigest])
		for _, arch := range arches {
			fromRegistry := contractPlatformImage(t, registryIndex, registryManifest, arch)
			fromLayout := contractPlatformImage(t, layoutIndex, layoutManifest, arch)
			assertContractOrigin(t, fromLayout, children[arch], application)
			registryRaw, err := fromRegistry.Manifest()
			require.NoError(t, err)
			layoutRaw, err := fromLayout.Manifest()
			require.NoError(t, err)
			require.Equal(t, originAnnotations(registryRaw.Annotations), originAnnotations(layoutRaw.Annotations), "manifest origin for %s", arch)
			require.Equal(t, contractLabels(t, fromRegistry)["BaseImage"], contractLabels(t, fromLayout)["BaseImage"])
			require.Equal(t, originAnnotations(contractLabels(t, fromRegistry)), originAnnotations(contractLabels(t, fromLayout)), "config origin for %s", arch)
			assertContractLayers(t, fromLayout, originals[arch], false)
			verifyOriginBlobs(t, fromLayout)
		}
	})

	t.Run("unrecoverable-origin", func(t *testing.T) {
		// P1 records an original that neither the registry nor the builder has,
		// as after A is deleted and the builder cache is cold. A builder that
		// still caches A's digest can rebuild from it, which is still exact.
		require.NoError(t, patch(repo+":original", "unrecoverable-p1", originTestReport(t, originAMD64), nil))
		p1 := contractImage(t, ctx, repo+":unrecoverable-p1")
		missing := digest.FromString("deleted original A").String()
		cfg, err := p1.ConfigFile()
		require.NoError(t, err)
		cfg = cfg.DeepCopy()
		cfg.Config.Labels[types.AnnotationPatchOriginDigest] = missing
		input, err := mutate.ConfigFile(p1, cfg)
		require.NoError(t, err)
		manifest, err := p1.Manifest()
		require.NoError(t, err)
		annotations := maps.Clone(manifest.Annotations)
		annotations[types.AnnotationPatchOriginDigest] = missing
		input = originAnnotatedImage(t, input, annotations)
		require.NoError(t, remote.Write(originTestReference(t, repo+":unrecoverable-input"), input, remote.WithContext(ctx)))
		_, err = remote.Get(originTestReference(t, repo+"@"+missing), remote.WithContext(ctx))
		require.Error(t, err, "the recorded original must be unavailable")
		err = patch(repo+":unrecoverable-input", "unrecoverable-p2", originTestReport(t, originAMD64), func(opts *types.Options) { opts.IgnoreError = true })
		require.ErrorContains(t, err, "restore the original image")
		_, err = remote.Get(originTestReference(t, repo+":unrecoverable-p2"), remote.WithContext(ctx))
		require.Error(t, err, "a failed recovery must not publish output")
	})
}

func contractImage(t *testing.T, ctx context.Context, ref string) v1.Image {
	t.Helper()
	img, err := remote.Image(originTestReference(t, ref), remote.WithContext(ctx))
	require.NoError(t, err)
	return img
}

func contractLabels(t *testing.T, img v1.Image) map[string]string {
	t.Helper()
	cfg, err := img.ConfigFile()
	require.NoError(t, err)
	return cfg.Config.Labels
}

// assertContractOrigin checks the manifest annotations and config labels of a
// patched image for the exact original digest and preserved application metadata.
func assertContractOrigin(t *testing.T, img v1.Image, original string, application map[string]string) {
	t.Helper()
	manifest, err := img.Manifest()
	require.NoError(t, err)
	for _, surface := range []map[string]string{manifest.Annotations, contractLabels(t, img)} {
		require.Equal(t, types.PatchOriginImage, surface[types.AnnotationPatchOriginKind])
		require.Equal(t, original, surface[types.AnnotationPatchOriginDigest])
		require.NotEmpty(t, surface[types.AnnotationPatchOriginName])
		for key, value := range application {
			require.Equal(t, value, surface[key], "application metadata %s", key)
		}
	}
}

// assertContractLayers checks that the original layers come first. A re-patch
// must replace P1's patch layer, leaving exactly one patch layer on top of A.
func assertContractLayers(t *testing.T, img v1.Image, original v1.Image, repatch bool) {
	t.Helper()
	manifest, err := img.Manifest()
	require.NoError(t, err)
	base, err := original.Manifest()
	require.NoError(t, err)
	require.Greater(t, len(manifest.Layers), len(base.Layers))
	if repatch {
		require.Len(t, manifest.Layers, len(base.Layers)+1, "the previous patch layer is replaced, not stacked")
	}
	for i := range base.Layers {
		require.Equal(t, base.Layers[i].Digest, manifest.Layers[i].Digest)
	}
}

func contractPlatformImage(t *testing.T, index v1.ImageIndex, manifest *v1.IndexManifest, arch string) v1.Image {
	t.Helper()
	for i := range manifest.Manifests {
		desc := &manifest.Manifests[i]
		if desc.Platform != nil && desc.Platform.OS == LINUX && desc.Platform.Architecture == arch {
			img, err := index.Image(desc.Digest)
			require.NoError(t, err)
			return img
		}
	}
	require.FailNow(t, "missing platform", arch)
	return nil
}

func originAnnotations(values map[string]string) map[string]string {
	origin := map[string]string{}
	for _, key := range []string{types.AnnotationPatchOriginKind, types.AnnotationPatchOriginName, types.AnnotationPatchOriginDigest} {
		if value, ok := values[key]; ok {
			origin[key] = value
		}
	}
	return origin
}

func removeContractImage(t *testing.T, image string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", "image", "rm", image).CombinedOutput() // #nosec G204 -- test-owned image name.
	if err != nil {
		t.Logf("remove %s: %v: %s", image, err, output)
	}
}
