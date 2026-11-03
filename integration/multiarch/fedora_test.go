package integration

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/project-copacetic/copacetic/integration/common"
	"github.com/project-copacetic/copacetic/pkg/imageloader"
	"github.com/stretchr/testify/require"
)

func TestPatchFedora45(t *testing.T) {
	const sourceRef = "localhost:5000/fedora:45-cli-source"
	arches := []string{"amd64", "arm64"}
	copyImage(t, common.Fedora45Image, sourceRef)

	before := make(map[string]string, len(arches))
	for _, arch := range arches {
		before[arch] = common.FedoraReleaseVersion(t, sourceRef, "linux/"+arch, imageloader.Docker)
		require.Equal(t, "45-0.10", before[arch], "pinned Fedora fixture must contain the outdated RPM on %s", arch)
	}

	reportDir := t.TempDir()
	for _, arch := range arches {
		common.WriteFedoraReleaseManifest(t, reportDir, arch, before[arch])
	}
	const tag = "45-cli-native-patched"
	args := []string{
		"patch", "-i=" + sourceRef, "-t=" + tag,
		"--push", "--timeout=30m", "--ignore-errors=false", "--debug",
		"-r=" + reportDir, "-s=native",
	}
	if buildkitAddr != "" {
		args = append(args, "-a="+buildkitAddr)
	}

	cmd := exec.Command(copaPath, args...) // #nosec G204 -- arguments are fixed integration fixtures.
	cmd.Env = append(os.Environ(), common.DockerDINDAddress.Env()...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "copa patch Fedora 45: %s", string(out))

	patchedRef := fmt.Sprintf("localhost:5000/fedora:%s", tag)
	for _, arch := range arches {
		after := common.FedoraReleaseVersion(t, patchedRef, "linux/"+arch, imageloader.Docker)
		common.RequireFedoraReleaseUpgrade(t, before[arch], after)
	}
}
