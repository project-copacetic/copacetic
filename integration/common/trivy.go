package common

import (
	_ "embed"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed fixtures/trivy_ignore.rego
var TrivyIgnore []byte

// Pinned Trivy DB manifest digests used by every integration-test scan. The `:2`
// tag rotates ~6 times per day as new CVEs are added; pinning to a digest makes
// the test suite reproducible and decouples PR CI from the upstream DB-publish
// cadence. Both the primary (GHCR) and fallback (ECR) are pinned independently —
// otherwise a transient GHCR auth/rate-limit/network failure would silently fall
// back to the unpinned ECR mirror and reintroduce non-determinism.
//
// Bump these together as part of any test-fixture refresh (e.g., when bumping the
// pinned base-image SHAs in integration/singlearch/fixtures/test-images.json) so
// the DB's "fixed-in" versions stay reachable from the test images' package
// mirrors.
//
// To resolve current digests:
//
//	curl -fsSL -I -H "Accept: application/vnd.oci.image.index.v1+json" \
//	  -H "Authorization: Bearer $(curl -fsSL 'https://ghcr.io/token?scope=repository:aquasecurity/trivy-db:pull' | jq -r .token)" \
//	  https://ghcr.io/v2/aquasecurity/trivy-db/manifests/2 | grep -i docker-content-digest
//
//	curl -fsSL -I -H "Accept: application/vnd.oci.image.manifest.v1+json" \
//	  -H "Authorization: Bearer $(curl -fsSL 'https://public.ecr.aws/token/' | jq -r .token)" \
//	  https://public.ecr.aws/v2/aquasecurity/trivy-db/manifests/2 | grep -i docker-content-digest
const (
	trivyDBPrimary  = "ghcr.io/aquasecurity/trivy-db@sha256:ef6b25b723730a44618a67a337ac48a73fbf257ef2cda34433d9fb305ac7fa5a"
	trivyDBFallback = "public.ecr.aws/aquasecurity/trivy-db@sha256:2ae934bb83e67ee3865228894fc7eb61bdeed43e50764a51260b794818ef917f"
)

// trivyDBRepositories is the comma-separated `--db-repository` value passed to
// every `trivy image` invocation: primary, then ECR fallback.
var trivyDBRepositories = trivyDBPrimary + "," + trivyDBFallback

type ScannerCmd struct {
	Output       string
	SkipDBUpdate bool
	IgnoreFile   string
	ExitCode     int
	Platform     string
	ImageSrc     string
	CacheDir     string
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

func (s *ScannerCmd) WithCacheDir(cacheDir string) *ScannerCmd {
	s.CacheDir = cacheDir
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
	if s.CacheDir != "" {
		args = append(args, "--cache-dir="+s.CacheDir)
	}

	args = append(args, ref)

	const maxRetries = 3
	var out []byte
	var err error
	for attempt := range maxRetries {
		cmd := exec.Command(args[0], args[1:]...) //#nosec G204
		cmd.Env = append(os.Environ(), envVars...)
		out, err = cmd.CombinedOutput()
		if err == nil {
			break
		}
		if !isTransientScanError(string(out)) || attempt == maxRetries-1 {
			break
		}
		t.Logf("trivy scan attempt %d/%d failed with transient error, retrying: %s", attempt+1, maxRetries, string(out))
	}

	assert.NoError(t, err, string(out))
}

// isTransientScanError returns true for network/IO errors that may succeed on retry.
func isTransientScanError(output string) bool {
	return strings.Contains(output, "unexpected EOF") ||
		strings.Contains(output, "connection reset") ||
		strings.Contains(output, "deadline exceeded") ||
		strings.Contains(output, "cache may be in use")
}

func DownloadDB(t *testing.T, envVars ...string) {
	args := []string{
		"trivy",
		"image",
		"--download-db-only",
		"--db-repository=" + trivyDBRepositories,
	}
	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, envVars...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

// DownloadDBToDir downloads the Trivy vulnerability database to a specific cache directory.
func DownloadDBToDir(t *testing.T, cacheDir string, envVars ...string) {
	t.Helper()
	args := []string{
		"trivy",
		"image",
		"--download-db-only",
		"--db-repository=" + trivyDBRepositories,
		"--cache-dir=" + cacheDir,
	}
	cmd := exec.Command(args[0], args[1:]...) //#nosec G204
	cmd.Env = append(cmd.Env, os.Environ()...)
	cmd.Env = append(cmd.Env, envVars...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}

// CopyCacheDir creates a per-test copy of the Trivy cache directory to avoid
// concurrent cache lock contention between parallel tests.
// Uses hardlinks for data files to avoid expensive copies (the DB files are read-only during scans).
func CopyCacheDir(t *testing.T, srcCacheDir string) string {
	t.Helper()
	dstCacheDir := filepath.Join(t.TempDir(), "trivy-cache")
	require.NoError(t, os.MkdirAll(filepath.Join(dstCacheDir, "db"), 0o755))

	entries, err := os.ReadDir(filepath.Join(srcCacheDir, "db"))
	require.NoError(t, err)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		src := filepath.Join(srcCacheDir, "db", entry.Name())
		dst := filepath.Join(dstCacheDir, "db", entry.Name())
		// Use hardlink instead of copy - DB files are read-only during scans
		// and hardlinks share the same inode, avoiding ~700MB copy per goroutine
		if err := os.Link(src, dst); err != nil {
			// Fall back to copy if hardlink fails (e.g., cross-device)
			if err := copyFile(src, dst); err != nil {
				require.NoError(t, err)
			}
		}
	}
	return dstCacheDir
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
