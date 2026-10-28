package integration

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/project-copacetic/copacetic/integration/common"
	"github.com/stretchr/testify/require"
)

// TestPatchFedora45 exercises the CLI without relying on Trivy's Fedora support.
// The CI matrix runs it once with a native report and once without a report.
func TestPatchFedora45(t *testing.T) {
	const platform = "linux/amd64"
	before := common.FedoraReleaseVersion(t, common.Fedora45Image, platform)
	require.Equal(t, "45-0.10", before, "pinned Fedora fixture must contain the outdated RPM")

	tag := "45-fedora-cli-reportless"
	if reportFile {
		tag = "45-fedora-cli-native"
	}
	args := []string{"patch", "-i=" + common.Fedora45Image, "-t=" + tag,
		"--timeout=30m", "--ignore-errors=false", "--debug"}
	if buildkitAddr != "" {
		args = append(args, "-a="+buildkitAddr)
	}
	if reportFile {
		report := common.WriteFedoraReleaseManifest(t, t.TempDir(), "amd64", before)
		args = append(args, "-r="+report, "-s=native")
	} else {
		args = append(args, "--platform="+platform)
	}

	unsuffixedRef := fmt.Sprintf("docker.io/library/fedora:%s", tag)
	patchedRef := unsuffixedRef
	if !reportFile {
		patchedRef += "-amd64"
	}
	removeDockerImages(t, patchedRef, unsuffixedRef)

	cmd := exec.Command(copaPath, args...) // #nosec G204 -- arguments are fixed integration fixtures.
	cmd.Env = append(os.Environ(), common.DockerDINDAddress.Env()...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "copa patch Fedora 45: %s", string(out))

	patchedRef = waitForDockerImage(t, patchedRef, unsuffixedRef)
	after := common.FedoraReleaseVersion(t, patchedRef, platform)
	common.RequireFedoraReleaseUpgrade(t, before, after)
}
