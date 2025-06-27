package common

import (
	_ "embed"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed fixtures/trivy_ignore.rego
var TrivyIgnore []byte

type ScannerCmd struct {
	Output       string
	SkipDBUpdate bool
	IgnoreFile   string
	ExitCode     int
	Platform     string
	ImageSrc     string
}

func NewScanner() *ScannerCmd {
	return &ScannerCmd{}
}

func (s *ScannerCmd) WithOutput(output string) *ScannerCmd {
	s.Output = output
	return s
}

func (s *ScannerCmd) WithSkipDBUpdate() *ScannerCmd {
	s.SkipDBUpdate = true
	return s
}

func (s *ScannerCmd) WithIgnoreFile(ignoreFile string) *ScannerCmd {
	s.IgnoreFile = ignoreFile
	return s
}

func (s *ScannerCmd) WithExitCode(exitCode int) *ScannerCmd {
	s.ExitCode = exitCode
	return s
}

func (s *ScannerCmd) WithPlatform(platform string) *ScannerCmd {
	s.Platform = platform
	return s
}

func (s *ScannerCmd) WithImageSrc(imageSrc string) *ScannerCmd {
	s.ImageSrc = imageSrc
	return s
}

func (s *ScannerCmd) Scan(t *testing.T, ref string, ignoreErrors bool, envVars ...string) {
	args := []string{
		"trivy",
		"image",
		"--quiet",
		"--pkg-types=os",
		"--ignore-unfixed",
		"--scanners=vuln",
	}
	if s.Output != "" {
		args = append(args, []string{"-o=" + s.Output, "-f=json"}...)
	}
	if s.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}
	if s.IgnoreFile != "" {
		args = append(args, "--ignore-policy="+s.IgnoreFile)
	}
	// If ignoreErrors is false, we expect a non-zero exit code.
	if s.ExitCode != 0 && !ignoreErrors {
		args = append(args, "--exit-code="+strconv.Itoa(s.ExitCode))
	}
	if s.Platform != "" {
		args = append(args, "--platform="+s.Platform)
	}
	if s.ImageSrc != "" {
		args = append(args, "--image-src="+s.ImageSrc)
	}

	args = append(args, ref)
	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, envVars...)
	out, err := cmd.CombinedOutput()

	assert.NoError(t, err, string(out))
}

func DownloadDB(t *testing.T, envVars ...string) {
	args := []string{
		"trivy",
		"image",
		"--download-db-only",
		"--db-repository=ghcr.io/aquasecurity/trivy-db:2,public.ecr.aws/aquasecurity/trivy-db",
	}
	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, envVars...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
