package patch

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"text/tabwriter"
	"time"

	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	buildkitclient "github.com/moby/buildkit/client"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestRemoveIfNotDebug(t *testing.T) {
	// Test removing working folder when not in debug mode
	t.Run("RemoveWorkingFolder", func(t *testing.T) {
		// Set log level to Info to simulate not being in debug mode
		log.SetLevel(log.InfoLevel)

		// Create a temporary working folder
		workingFolder := t.TempDir()
		defer os.RemoveAll(workingFolder)

		removeIfNotDebug(workingFolder)

		// Check that the working folder was removed
		if _, err := os.Stat(workingFolder); err == nil {
			t.Errorf("Working folder should have been removed but still exists")
		}
	})

	// Test not removing working folder when in debug mode
	t.Run("KeepWorkingFolderDebug", func(t *testing.T) {
		// Set log level to Debug to simulate being in debug mode
		log.SetLevel(log.DebugLevel)

		// Create a temporary working folder
		workingFolder := t.TempDir()

		removeIfNotDebug(workingFolder)

		// Check that the working folder still exists
		if _, err := os.Stat(workingFolder); err != nil {
			t.Errorf("Working folder should have been kept but was removed")
		}

		// Clean up the working folder manually
		os.RemoveAll(workingFolder)
	})

	t.Run("RemoveWorkingFolderWhenLogLevelIsInfo", func(t *testing.T) {
		log.SetLevel(log.InfoLevel)
		workingFolder := t.TempDir()

		removeIfNotDebug(workingFolder)

		// folder should be removed
		if _, err := os.Stat(workingFolder); err == nil {
			t.Errorf("working folder should have been removed but still exists at: %s", workingFolder)
		}
	})

	t.Run("KeepWorkingFolderWhenLogLevelIsDebug", func(t *testing.T) {
		log.SetLevel(log.DebugLevel)
		workingFolder := t.TempDir()

		removeIfNotDebug(workingFolder)

		// folder should remain
		if _, err := os.Stat(workingFolder); err != nil {
			t.Errorf("working folder should have been kept but was removed at: %s", workingFolder)
		}
	})

	t.Run("NoopWhenFolderDoesNotExist", func(t *testing.T) {
		log.SetLevel(log.InfoLevel)
		// create then remove
		workingFolder := t.TempDir()
		os.RemoveAll(workingFolder)

		removeIfNotDebug(workingFolder)

		// still doesn't exist, and no panic
		if _, err := os.Stat(workingFolder); err == nil {
			t.Errorf("folder unexpectedly re-created: %s", workingFolder)
		}
	})
}

func TestGetRepoNameWithDigest(t *testing.T) {
	result := common.GetRepoNameWithDigest("docker.io/library/nginx:1.21.6-patched", "sha256:mocked-digest")
	if result != "nginx@sha256:mocked-digest" {
		t.Fatalf("unexpected result: %s", result)
	}
	t.Run("WithTagAndDigest", func(t *testing.T) {
		result := common.GetRepoNameWithDigest("docker.io/library/nginx:1.21.6-patched", "sha256:mocked-digest")
		assert.Equal(t, "nginx@sha256:mocked-digest", result)
	})

	t.Run("NoTagUsesFullImageName", func(t *testing.T) {
		result := common.GetRepoNameWithDigest("docker.io/library/nginx", "sha256:abc123")
		// there's no trailing :tag, so we strip library/ prefix -> "nginx@sha256:abc123"
		assert.Equal(t, "nginx@sha256:abc123", result)
	})

	t.Run("RandomLocalImageName", func(t *testing.T) {
		result := common.GetRepoNameWithDigest("localhost:5000/repo/image:mytag", "sha256:abcdef1234")
		// last portion is "image:mytag" => we only keep "image" for the name portion
		assert.Equal(t, "image@sha256:abcdef1234", result)
	})

	t.Run("NoRegistryNoTag", func(t *testing.T) {
		result := common.GetRepoNameWithDigest("myimage", "sha256:short")
		// no registry, no tag, just "myimage" => name is "myimage@sha256:short"
		assert.Equal(t, "myimage@sha256:short", result)
	})
}

func TestResolvePatchedTag(t *testing.T) {
	tests := []struct {
		name        string
		image       string
		explicitTag string
		suffix      string
		want        string
		wantErr     bool
	}{
		{
			name:  "no explicitTag, no suffix, existing base tag",
			image: "docker.io/library/nginx:1.23",
			want:  "1.23-patched",
		},
		{
			name:    "no explicitTag, no suffix, no base tag",
			image:   "docker.io/library/nginx",
			wantErr: true,
		},
		{
			name:   "explicitTag overrides suffix and base tag",
			image:  "docker.io/library/nginx:1.23",
			suffix: "xyz",
			// user sets an explicit tag, so we don't append the suffix
			explicitTag: "my-funky-tag",
			want:        "my-funky-tag",
		},
		{
			name:   "custom suffix with base tag",
			image:  "docker.io/library/nginx:1.23",
			suffix: "security",
			want:   "1.23-security",
		},
		{
			name:    "custom suffix with no base tag",
			image:   "docker.io/library/nginx",
			suffix:  "foo",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// tags should always resolve here
			imageRef, err := reference.ParseNormalizedNamed(tc.image)
			if err != nil {
				t.Fatalf("failed to parse image reference: %v", err)
			}

			got, err := common.ResolvePatchedTag(imageRef, tc.explicitTag, tc.suffix)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func init() {
	bkNewClient = func(ctx context.Context, _ buildkit.Opts) (*buildkitclient.Client, error) {
		// a path that certainly does not have a BuildKit daemon listening.
		return buildkitclient.New(ctx, "unix:///tmp/nowhere.sock")
	}
}

func TestPatch_BuildReturnsNilResponse(t *testing.T) {
	// This test verifies that Patch() handles errors gracefully and doesn't panic
	// when the BuildKit connection fails.

	targetPlatforms := []string{"linux/amd64"}

	opts := &types.Options{
		Image:             "alpine:3.19",
		Timeout:           30 * time.Second,
		Push:              false,
		Platforms:         targetPlatforms,
		PkgTypes:          "os",
		LibraryPatchLevel: "patch",
		Progress:          "quiet",
	}
	err := Patch(context.Background(), opts)

	// We expect an error since BuildKit client points to a non-existent socket
	if err == nil {
		t.Fatalf("expected error from Patch(), got nil")
	}

	// The test mainly verifies that Patch doesn't panic and returns an error.
	// The exact error message may vary depending on how far the patch process gets
	// before failing (BuildKit connection, image loading, etc.)
	t.Logf("Patch returned error as expected (and did not panic): %v", err)
}

func TestPatchWithContextDerivesImplicitPlatformFromReport(t *testing.T) {
	const (
		amd64Arch      = "amd64"
		alpineImageRef = "docker.io/library/alpine:3.20"
		patchedTag     = "patched"
		trivyScanner   = "trivy"
	)

	hostArch := common.GetDefaultLinuxPlatform().Architecture
	reportArch := ARM64
	if hostArch == reportArch {
		reportArch = amd64Arch
	}

	reportData, err := os.ReadFile("../report/testdata/trivy_valid.json")
	require.NoError(t, err)
	var reportJSON map[string]any
	require.NoError(t, json.Unmarshal(reportData, &reportJSON))
	metadata, ok := reportJSON["Metadata"].(map[string]any)
	require.True(t, ok)
	imageConfig, ok := metadata["ImageConfig"].(map[string]any)
	require.True(t, ok)
	imageConfig["architecture"] = reportArch
	reportData, err = json.Marshal(reportJSON)
	require.NoError(t, err)

	reportPath := t.TempDir() + "/report.json"
	require.NoError(t, os.WriteFile(reportPath, reportData, 0o600))

	originalBKNewClient := bkNewClient
	buildkitCalled := false
	buildkitErr := errors.New("buildkit reached after implicit report platform resolution")
	bkNewClient = func(context.Context, buildkit.Opts) (*buildkitclient.Client, error) {
		buildkitCalled = true
		return nil, buildkitErr
	}
	t.Cleanup(func() { bkNewClient = originalBKNewClient })

	err = patchWithContext(context.Background(), &types.Options{
		Image:             alpineImageRef,
		Report:            reportPath,
		PatchedTag:        patchedTag,
		Scanner:           trivyScanner,
		PkgTypes:          "os",
		LibraryPatchLevel: "patch",
	})

	assert.ErrorIs(t, err, buildkitErr)
	assert.True(t, buildkitCalled, "implicit report architecture should be resolved before BuildKit creation")
}

func TestResolveSingleReportPlatform(t *testing.T) {
	const linuxARM64Platform = "linux/arm64"

	tests := []struct {
		name      string
		platforms []string
		updates   *unversioned.UpdateManifest
		want      string
		wantErr   string
	}{
		{
			name: "defaults to host platform without report architecture",
			want: platforms.Format(common.GetDefaultLinuxPlatform()),
		},
		{
			name: "derives implicit platform from report metadata",
			updates: &unversioned.UpdateManifest{Metadata: unversioned.Metadata{
				Config: unversioned.Config{Arch: "aarch64", Variant: "v8"},
			}},
			want: linuxARM64Platform,
		},
		{
			name:      "explicit platform",
			platforms: []string{"linux/amd64"},
			want:      "linux/amd64",
		},
		{
			name:      "explicit platform is not replaced by report metadata",
			platforms: []string{"linux/amd64"},
			updates: &unversioned.UpdateManifest{Metadata: unversioned.Metadata{
				Config: unversioned.Config{Arch: ARM64},
			}},
			want: "linux/amd64",
		},
		{
			name:      "normalizes variant",
			platforms: []string{"linux/arm64/v8"},
			want:      "linux/arm64",
		},
		{
			name:      "rejects multiple platforms",
			platforms: []string{"linux/amd64", "linux/arm64"},
			wantErr:   "a single report file can target only one platform",
		},
		{
			name:      "rejects unsupported platform",
			platforms: []string{"linux/mips64"},
			wantErr:   "unsupported platform",
		},
		{
			name: "rejects unsupported report platform",
			updates: &unversioned.UpdateManifest{Metadata: unversioned.Metadata{
				Config: unversioned.Config{Arch: "bogus", Variant: "v1"},
			}},
			wantErr: "unsupported scan report platform",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveSingleReportPlatformWithUpdates(tt.platforms, tt.updates)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got.String())
		})
	}
}

func TestArchTag(t *testing.T) {
	cases := []struct {
		base, arch, variant, want string
	}{
		{"patched", "arm64", "", "patched-arm64"},
		{"patched", "arm", "v7", "patched-arm-v7"},
		{"patched", "mips64", "n32", "patched-mips64-n32"},
	}
	for _, c := range cases {
		got := archTag(c.base, c.arch, c.variant)
		if got != c.want {
			t.Fatalf("archTag(%q,%q,%q) = %q, want %q", c.base, c.arch, c.variant, got, c.want)
		}
	}
}

func TestNormalizeConfigForPlatform(t *testing.T) {
	// minimal starting config (missing fields on purpose)
	orig := []byte(`{"architecture":"amd64"}`)

	plat := &types.PatchPlatform{}
	plat.OS = "linux"
	plat.Architecture = "arm64"
	plat.Variant = "v8"

	fixed, err := normalizeConfigForPlatform(orig, plat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var m map[string]string
	if err := json.Unmarshal(fixed, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if m["architecture"] != "arm64" || m["os"] != "linux" || m["variant"] != "v8" {
		t.Fatalf("fields not normalised correctly: %#v", m)
	}

	// when Variant empty, key should be removed
	var m2 map[string]string
	plat.Variant = ""
	fixed, _ = normalizeConfigForPlatform(orig, plat)
	err = json.Unmarshal(fixed, &m2)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m2["variant"]; ok {
		t.Errorf("variant key should be dropped when empty")
	}
}

func TestMultiPlatformSummaryTable(t *testing.T) {
	platforms := []struct {
		OS           string
		Architecture string
		Variant      string
	}{
		{"linux", "amd64", ""},
		{"linux", "arm64", ""},
		{"linux", "arm", "v7"},
		{"windows", "amd64", ""},
	}

	summaryMap := map[string]*types.MultiPlatformSummary{
		"linux/amd64": {
			Platform: "linux/amd64",
			Status:   "Patched",
			Ref:      "docker.io/library/nginx:patched-amd64",
			Message:  "",
		},
		"linux/arm64": {
			Platform: "linux/arm64",
			Status:   "Error",
			Ref:      "",
			Message:  "emulation is not enabled for platform linux/arm64",
		},
		"linux/arm/v7": {
			Platform: "linux/arm/v7",
			Status:   "Ignored",
			Ref:      "",
			Message:  "",
		},
		"windows/amd64": {
			Platform: "windows/amd64",
			Status:   "Not Patched",
			Ref:      "docker.io/library/nginx (original reference)",
			Message:  "Windows Image (Original Preserved)",
		},
	}

	var b strings.Builder
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	_, _ = w.Write([]byte("PLATFORM\tSTATUS\tREFERENCE\tMESSAGE\n"))
	for _, p := range platforms {
		platformKey := buildkit.PlatformKey(ispec.Platform{
			OS:           p.OS,
			Architecture: p.Architecture,
			Variant:      p.Variant,
		})
		s := summaryMap[platformKey]
		if s != nil {
			ref := s.Ref
			if ref == "" {
				ref = "-"
			}
			_, _ = w.Write([]byte(
				s.Platform + "\t" + s.Status + "\t" + ref + "\t" + s.Message + "\n",
			))
		}
	}
	w.Flush()

	got := b.String()
	expected := `PLATFORM       STATUS       REFERENCE                                     MESSAGE
linux/amd64    Patched      docker.io/library/nginx:patched-amd64
linux/arm64    Error        -                                             emulation is not enabled for platform linux/arm64
linux/arm/v7   Ignored      -
windows/amd64  Not Patched  docker.io/library/nginx (original reference)  Windows Image (Original Preserved)
`
	gotLines := strings.FieldsFunc(got, func(r rune) bool { return r == '\n' || r == '\r' })
	expectedLines := strings.FieldsFunc(expected, func(r rune) bool { return r == '\n' || r == '\r' })
	if len(gotLines) != len(expectedLines) {
		t.Errorf("line count mismatch:\ngot:\n%s\nwant:\n%s", got, expected)
	}
	for i := range gotLines {
		if strings.TrimSpace(gotLines[i]) != strings.TrimSpace(expectedLines[i]) {
			t.Errorf("line %d mismatch:\ngot:   %q\nwant:  %q", i+1, gotLines[i], expectedLines[i])
		}
	}
}
