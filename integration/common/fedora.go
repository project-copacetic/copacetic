package common

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	rpmver "github.com/knqyf263/go-rpm-version"
	"github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
	"github.com/stretchr/testify/require"
)

// Fedora45Image pins a Fedora 45 index with an outdated release package on
// both amd64 and arm64, so an upgrade can be observed in integration tests.
const Fedora45Image = "docker.io/library/fedora@sha256:aacbc26b38361ba0cb3d10f268da40b61b36aed6ed6fe5831a35871636bedb06"

const (
	Fedora45ReleasePackage = "fedora-release-container"
	// The test checks a real upgrade from 45-0.10, without depending on which
	// newer Fedora release happens to be available or cached by BuildKit.
	fedora45MinimumFixedVersion = "45-0.11"
)

// FedoraReleaseVersion reads the installed RPM from a container image.
func FedoraReleaseVersion(t *testing.T, image, platform string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	args := []string{"run", "--rm", "--platform", platform, "--entrypoint", "rpm", image,
		"-q", "--qf", "%{VERSION}-%{RELEASE}", Fedora45ReleasePackage}
	cmd := exec.CommandContext(ctx, "docker", args...) // #nosec G204 -- image and platform are fixed integration fixtures.
	cmd.Env = append(os.Environ(), DockerDINDAddress.Env()...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "querying %s on %s: %s", Fedora45ReleasePackage, image, string(out))
	return strings.TrimSpace(string(out))
}

// WriteFedoraReleaseManifest creates a native Copa report for one architecture.
func WriteFedoraReleaseManifest(t *testing.T, dir, arch, installedVersion string) string {
	t.Helper()
	manifest := v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
		Metadata: v1alpha1.Metadata{
			OS:     v1alpha1.OS{Type: "fedora", Version: "45"},
			Config: v1alpha1.Config{Arch: arch},
		},
		Updates: v1alpha1.UpdatePackages{{
			Name: Fedora45ReleasePackage, InstalledVersion: installedVersion,
			FixedVersion: fedora45MinimumFixedVersion, VulnerabilityID: "CVE-2023-TEST",
		}},
	}
	data, err := json.Marshal(manifest)
	require.NoError(t, err)
	path := filepath.Join(dir, "fedora-"+arch+".json")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// RequireFedoraReleaseUpgrade checks that the pinned RPM was actually updated.
func RequireFedoraReleaseUpgrade(t *testing.T, before, after string) {
	t.Helper()
	require.Equal(t, "45-0.10", before, "pinned Fedora fixture must contain the outdated RPM")
	oldVersion, newVersion := rpmver.NewVersion(before), rpmver.NewVersion(after)
	require.True(t, oldVersion.LessThan(newVersion), "RPM must change: before=%s after=%s", before, after)
	require.False(t, newVersion.LessThan(rpmver.NewVersion(fedora45MinimumFixedVersion)),
		"patched RPM %s must meet the fixed version", after)
	t.Logf("%s: %s -> %s", Fedora45ReleasePackage, before, after)
}
