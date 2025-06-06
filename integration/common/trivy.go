package common

import (
	_ "embed"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	//go:embed fixtures/trivy_ignore.rego
	TrivyIgnore []byte
)

func DownloadDB(t *testing.T, envVars ...string) {
	args := []string{
		"trivy",
		"image",
		"--download-db-only",
	}
	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, envVars...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
