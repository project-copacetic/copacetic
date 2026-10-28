package patch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
)

// Re-encode an actual patched manifest without Copa annotations, as a Docker
// list or legacy producer may do, retaining its real layers and config labels.
type unclaimedManifestImage struct{ v1.Image }

func (i unclaimedManifestImage) Manifest() (*v1.Manifest, error) {
	manifest, err := i.Image.Manifest()
	if err != nil {
		return nil, err
	}
	manifest = manifest.DeepCopy()
	for key := range manifest.Annotations {
		if strings.HasPrefix(key, copaAnnotationKeyPrefix+".") {
			delete(manifest.Annotations, key)
		}
	}
	return manifest, nil
}

func testUnclaimedIndexOrigin(t *testing.T, ctx context.Context, addr, repo string, originals map[string]v1.Image, application map[string]string) {
	t.Helper()
	const (
		originalAncestry     = "original"
		modernDockerAncestry = "modern-docker"
		preserveOnly         = "preserve-only"
	)
	t.Run("unclaimed-index-origin", func(t *testing.T) {
		for _, ancestry := range []string{originalAncestry, "legacy", modernDockerAncestry, "mixed"} {
			t.Run(ancestry, func(t *testing.T) {
				var children []mutate.IndexAddendum
				for _, arch := range []string{originAMD64, "386"} {
					image := originals[arch]
					if ancestry != originalAncestry && (ancestry != "mixed" || arch != originAMD64) {
						var err error
						image, err = remote.Image(originTestReference(t, repo+":p1-"+arch), remote.WithContext(ctx))
						require.NoError(t, err)
						config, err := image.ConfigFile()
						require.NoError(t, err)
						config = config.DeepCopy()
						if ancestry != modernDockerAncestry {
							config.Config.Labels = withoutSourceLineageAnnotations(config.Config.Labels)
						}
						require.NotEmpty(t, config.Config.Labels["BaseImage"])
						image, err = mutate.ConfigFile(unclaimedManifestImage{image}, config)
						require.NoError(t, err)
						if ancestry == modernDockerAncestry {
							image = mutate.MediaType(image, v1types.DockerManifestSchema2)
						}
					}
					manifest, err := image.Manifest()
					require.NoError(t, err)
					children = append(children, mutate.IndexAddendum{Add: image, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: arch}, Annotations: manifest.Annotations}})
				}
				mediaType := v1types.OCIImageIndex
				if ancestry == modernDockerAncestry {
					mediaType = v1types.DockerManifestList
				}
				inputIndex := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, children...), mediaType)
				input := repo + ":unclaimed-" + ancestry
				require.NoError(t, remote.WriteIndex(originTestReference(t, input), inputIndex, remote.WithContext(ctx)))
				inputManifest, err := inputIndex.IndexManifest()
				require.NoError(t, err)
				require.Empty(t, inputManifest.Annotations, "input index carries no Copa origin or patched marker")
				inputDigest, err := inputIndex.Digest()
				require.NoError(t, err)
				for _, mode := range []string{"no-updates", "mixed-preserved", preserveOnly} {
					for _, export := range []string{"registry", "layout"} {
						if mode == preserveOnly && export == "layout" {
							continue
						} // Existing flow returns before layout export.
						t.Run(mode+"/"+export, func(t *testing.T) {
							reports := t.TempDir()
							for _, arch := range []string{originAMD64, "386"} {
								if mode == preserveOnly || (mode == "mixed-preserved" && arch == "386") {
									continue
								}
								report := fmt.Sprintf(`{"SchemaVersion":2,"ArtifactType":"container_image",
 "Metadata":{"OS":{"Family":"alpine","Name":"3.20.0"},"ImageConfig":{"architecture":%q}},
 "Results":[{"Class":"os-pkgs","Type":"alpine","Vulnerabilities":[]}]}`, arch)
								require.NoError(t, os.WriteFile(filepath.Join(reports, arch+".json"), []byte(report), 0o600))
							}
							output := repo + ":unclaimed-output-" + ancestry + "-" + mode + "-" + export
							opts := &types.Options{
								Image: input, Report: reports, Scanner: "trivy", PatchedTag: output,
								BkAddr: addr, PkgTypes: "os", Progress: "quiet", Timeout: 2 * time.Minute, Push: export == "registry",
							}
							if export == "layout" {
								opts.OCIDir = filepath.Join(t.TempDir(), "output")
							}
							err := Patch(ctx, opts)
							if mode == preserveOnly {
								require.ErrorIs(t, err, types.ErrNoUpdatesFound)
							} else {
								require.NoError(t, err)
							}
							var result v1.ImageIndex
							if export == "registry" {
								result, err = remote.Index(originTestReference(t, output), remote.WithContext(ctx))
							} else {
								var path layout.Path
								path, err = layout.FromPath(opts.OCIDir)
								require.NoError(t, err)
								result, err = path.ImageIndex()
							}
							require.NoError(t, err)
							manifest, err := result.IndexManifest()
							require.NoError(t, err)
							if ancestry == originalAncestry {
								require.Equal(t, inputDigest.String(), manifest.Annotations[types.AnnotationPatchOriginDigest])
							} else {
								for _, key := range []string{types.AnnotationPatchOriginKind, types.AnnotationPatchOriginName, types.AnnotationPatchOriginDigest} {
									require.NotContains(t, manifest.Annotations, key, "already-patched children cannot establish this index as original")
								}
							}
							require.ElementsMatch(t, inputManifest.Manifests, manifest.Manifests, "unchanged platform descriptors must be preserved")
							for i := range manifest.Manifests {
								child := &manifest.Manifests[i]
								image, err := result.Image(child.Digest)
								require.NoError(t, err)
								config, err := image.ConfigFile()
								require.NoError(t, err)
								for key, value := range application {
									require.Equal(t, value, config.Config.Labels[key])
								}
								verifyOriginBlobs(t, image)
							}
						})
					}
				}
			})
		}
	})
}
