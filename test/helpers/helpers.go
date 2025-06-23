package helpers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/project-copacetic/copacetic/test/testenv"
	"github.com/stretchr/testify/require"
)

func WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}

func OrasCopy(t *testing.T, src, dst string) {
	t.Helper()
	cmd := exec.Command("oras", "copy", src, dst, "--to-plain-http")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "oras copy failed for %s -> %s:\n%s", src, dst, string(out))
}

type TrivyCmd struct {
	t    *testing.T
	args []string
}

func Trivy(t *testing.T) *TrivyCmd {
	baseArgs := []string{
		"image",
		"--quiet",
		"--pkg-types=os",
		"--ignore-unfixed",
		"--scanners=vuln",
		"--skip-db-update",
	}
	return &TrivyCmd{t: t, args: baseArgs}
}

func (c *TrivyCmd) WithPlatform(platform string) *TrivyCmd {
	c.args = append(c.args, "--platform", platform)
	return c
}

func (c *TrivyCmd) WithOutput(path string) *TrivyCmd {
	c.args = append(c.args, "--format", "json", "--output", path)
	return c
}

func (c *TrivyCmd) WithIgnoreFile(path string) *TrivyCmd {
	c.args = append(c.args, "--ignore-policy", path)
	return c
}

func (c *TrivyCmd) WithExitCode(code int) *TrivyCmd {
	c.args = append(c.args, "--exit-code", strconv.Itoa(code))
	return c
}

func (c *TrivyCmd) WithImageSrc(src string) *TrivyCmd {
	c.args = append(c.args, "--image-src", src)
	return c
}

func (c *TrivyCmd) Scan(imageRef string) {
	c.t.Helper()
	c.args = append(c.args, imageRef)
	cmd := exec.Command("trivy", c.args...)
	out, err := cmd.CombinedOutput()
	require.NoError(c.t, err, "trivy scan failed for %s with args %v:\n%s", imageRef, c.args, string(out))
}

var trivyDBDownloaded sync.Once

func DownloadTrivyDB(t *testing.T) {
	t.Helper()
	trivyDBDownloaded.Do(func() {
		t.Log("Downloading Trivy vulnerability database...")
		args := []string{
			"image",
			"--download-db-only",
			"--db-repository=ghcr.io/aquasecurity/trivy-db:2",
		}
		cmd := exec.Command("trivy", args...)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "failed to download trivy db:\n%s", string(out))
		t.Log("Trivy DB downloaded successfully.")
	})
}

type CopaCmd struct {
	t    *testing.T
	env  *testenv.Env
	args []string
}

func Copa(t *testing.T, env *testenv.Env) *CopaCmd {
	return &CopaCmd{t: t, env: env}
}

func (c *CopaCmd) Patch(image, tag, reportPath string, ignoreErrors, push bool) *CopaCmd {
	copaPath := "../../bin/copa"
	c.args = []string{
		"patch",
		"--image=" + image,
		"--tag=" + tag,
		"--addr=" + c.env.Buildkit.Address,
		"--timeout=15m",
		"--debug",
	}
	if reportPath != "" {
		c.args = append(c.args, "--report="+reportPath)
	}
	if ignoreErrors {
		c.args = append(c.args, "--ignore-errors")
	}
	if push {
		c.args = append(c.args, "--push")
	}

	cmd := exec.Command(copaPath, c.args...)
	dockerConfigDir := c.t.TempDir()
	dockerConfig := fmt.Sprintf(`{ "insecure-registries": ["%s"] }`, c.env.Registry.Address)
	err := os.WriteFile(filepath.Join(dockerConfigDir, "config.json"), []byte(dockerConfig), 0600)
	require.NoError(c.t, err)
	cmd.Env = append(os.Environ(), "DOCKER_CONFIG="+dockerConfigDir)
	c.args = cmd.Args
	return c
}

func (c *CopaCmd) Run() {
	c.t.Helper()
	cmd := exec.Command(c.args[0], c.args[1:]...)
	cmd.Env = c.getCmdEnv()
	out, err := cmd.CombinedOutput()
	require.NoError(c.t, err, "copa command failed with args %v:\n%s", c.args, string(out))
}

func (c *CopaCmd) getCmdEnv() []string {
	dockerConfigDir := c.t.TempDir()
	dockerConfig := fmt.Sprintf(`{ "insecure-registries": ["%s"] }`, c.env.Registry.Address)
	err := os.WriteFile(filepath.Join(dockerConfigDir, "config.json"), []byte(dockerConfig), 0600)
	require.NoError(c.t, err)
	return append(os.Environ(), "DOCKER_CONFIG="+dockerConfigDir)
}
