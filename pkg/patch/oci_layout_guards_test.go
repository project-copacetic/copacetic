package patch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

// A layout input that can no longer be read after it was opened must stop the
// patch, rather than publishing an image without its manifest annotations.
func TestOCILayoutPatchStopsWhenManifestAnnotationsCannotBeRead(t *testing.T) {
	originalListWorkers := listWorkers
	t.Cleanup(func() { listWorkers = originalListWorkers })
	platform := ispec.Platform{OS: "linux", Architecture: "amd64"}
	listWorkers = func(context.Context, *client.Client) ([]*client.WorkerInfo, error) {
		return []*client.WorkerInfo{{ID: "oci-annotations-test", Platforms: []ispec.Platform{platform}}}, nil
	}

	source := openSolveTestSource(t)
	manifest := source.Descriptor.Digest
	require.NoError(t, os.Remove(filepath.Join(source.Path, "blobs", manifest.Algorithm().String(), manifest.Encoded())))
	updates := &unversioned.UpdateManifest{OSUpdates: unversioned.UpdatePackages{{
		Name: "openssl", InstalledVersion: "3.0.0-r0", FixedVersion: "3.0.1-r0", VulnerabilityID: "CVE-2099-0001",
	}}}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	result, err := patchSingleArchImageWithUpdates(ctx, &types.Options{
		OCISource:  source,
		PatchedTag: "registry.invalid/acme/app:patched",
		PkgTypes:   "os",
		Progress:   "quiet",
	}, types.PatchPlatform{Platform: platform}, false, nil, updates)
	require.ErrorContains(t, err, "read OCI layout manifest annotations for platform linux/amd64")
	require.Nil(t, result)
}

// Two reports for one layout platform must be rejected; otherwise the report
// read last would silently decide what is patched.
func TestOCILayoutRejectsMultipleReportsForOnePlatform(t *testing.T) {
	originalPatchPlatformImage := patchPlatformImage
	t.Cleanup(func() { patchPlatformImage = originalPatchPlatformImage })
	patchPlatformImage = func(
		context.Context, *types.Options, types.PatchPlatform, bool, chan<- *client.SolveStatus,
		*unversioned.UpdateManifest, string, string, map[string]string, digest.Digest,
	) (*types.PatchResult, error) {
		return nil, errors.New("no platform may be patched when reports conflict")
	}

	root, _, _ := writeTwoPlatformLayout(t)
	source, err := ocilayout.Open(t.Context(), root, "", "")
	require.NoError(t, err)
	reportDir := t.TempDir()
	for _, name := range []string{"amd64.json", "amd64-again.json"} {
		require.NoError(t, os.WriteFile(filepath.Join(reportDir, name), []byte(`{
			"SchemaVersion":2,"ArtifactName":"registry.invalid/acme/app:1.0","ArtifactType":"container_image",
			"Metadata":{"OS":{"Family":"alpine","Name":"3.21.0"},"ImageConfig":{"architecture":"amd64","os":"linux"}},
			"Results":[]
		}`), 0o600))
	}

	err = patchMultiPlatformImage(t.Context(), &types.Options{
		OCISource:  source,
		PatchedTag: "registry.invalid/acme/app:patched",
		Report:     reportDir,
		Scanner:    "trivy",
		PkgTypes:   "os",
		Progress:   "quiet",
	}, nil)
	require.ErrorContains(t, err, "multiple reports target OCI platform linux/amd64")
}

type recordingBuildClient struct {
	solveOpts []client.SolveOpt
}

//nolint:gocritic // buildkitBuildClient passes SolveOpt by value.
func (c *recordingBuildClient) Build(_ context.Context, solveOpt client.SolveOpt, _ string, _ gwclient.BuildFunc, _ chan *client.SolveStatus) (*client.SolveResponse, error) {
	c.solveOpts = append(c.solveOpts, solveOpt)
	return nil, errors.New("recorded without solving")
}

// The native Chisel preflight reads the target image through BuildKit, which
// can resolve a layout image only from the layout's content store.
func TestNativeChiselPreflightAttachesOCILayoutStore(t *testing.T) {
	source := openSolveTestSource(t)
	ref, err := source.ResolveReference()
	require.NoError(t, err)
	bkClient := &recordingBuildClient{}

	err = rejectTargetedNativeChiselPatch(t.Context(), bkClient, ref, &ispec.Platform{OS: "linux", Architecture: "amd64"}, source)
	require.ErrorContains(t, err, "inspect target image for native Chisel metadata")
	require.Len(t, bkClient.solveOpts, 1)
	require.Contains(t, bkClient.solveOpts[0].OCIStores, source.StoreID)
	require.NotNil(t, bkClient.solveOpts[0].OCIStores[source.StoreID])
}

// A VEX output that is a hard link to an input file would overwrite that
// input, so the patch must refuse it before any work starts.
func TestPatchRejectsVEXOutputHardLinkedToOCILayoutInput(t *testing.T) {
	source := openSolveTestSource(t)
	link := filepath.Join(t.TempDir(), "vex.json")
	require.NoError(t, os.Link(filepath.Join(source.Path, ispec.ImageIndexFile), link))

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err := patchWithContext(ctx, &types.Options{
		InputOCILayout: source.Path,
		OCIDir:         filepath.Join(t.TempDir(), "output"),
		PatchedTag:     "registry.invalid/acme/app:patched",
		Output:         link,
		Format:         "openvex",
		PkgTypes:       "os",
		Progress:       "quiet",
	})
	require.ErrorContains(t, err, "is the same file as OCI layout input file")
}
