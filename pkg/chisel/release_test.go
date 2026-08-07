package chisel

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ubuntuRelease2404 = "ubuntu-24.04"

func TestParseRelease(t *testing.T) {
	localDirectory := t.TempDir()
	canonicalLocalDirectory, err := filepath.Abs(localDirectory)
	require.NoError(t, err)

	tests := []struct {
		name        string
		value       string
		expected    Release
		errContains string
	}{
		{
			name:     "named release",
			value:    ubuntuRelease2404,
			expected: Release{Kind: ReleaseNamed, Location: ubuntuRelease2404},
		},
		{
			name:     "local directory",
			value:    localDirectory,
			expected: Release{Kind: ReleaseLocal, Location: canonicalLocalDirectory},
		},
		{
			name:  "pinned HTTPS Git URL",
			value: "https://example.com/chisel-releases.git#abc123",
			expected: Release{
				Kind:     ReleaseGit,
				Location: "https://example.com/chisel-releases.git",
				Revision: "abc123",
			},
		},
		{
			name:  "pinned Git tag with slash",
			value: "https://example.com/releases.git#release/24.04",
			expected: Release{
				Kind:     ReleaseGit,
				Location: "https://example.com/releases.git",
				Revision: "release/24.04",
			},
		},
		{
			name:        "empty",
			errContains: "override is empty",
		},
		{
			name:        "nonexistent local directory",
			value:       filepath.Join(t.TempDir(), "missing"),
			errContains: "neither a standard release name",
		},
		{
			name:        "unpinned Git URL",
			value:       "https://example.com/chisel-releases.git",
			errContains: "must include a pinned commit or tag fragment",
		},
		{
			name:        "symbolic Git revision",
			value:       "https://example.com/chisel-releases.git#HEAD",
			errContains: "must name a commit or tag",
		},
		{
			name:        "unsafe Git revision",
			value:       "https://example.com/chisel-releases.git#release..candidate",
			errContains: "invalid sequence",
		},
		{
			name:        "embedded credentials",
			value:       "https://user:" + strings.Repeat("s", 6) + "@example.com/chisel-releases.git#abc123",
			errContains: "must not contain embedded credentials",
		},
		{
			name:        "rejects cleartext Git URL",
			value:       "http://example.com/chisel-releases.git#abc123",
			errContains: "only public HTTPS URLs are supported",
		},
		{
			name:        "rejects SSH Git URL",
			value:       "ssh://git@example.com/chisel-releases.git#release/24.04",
			errContains: "only public HTTPS URLs are supported",
		},
		{
			name:        "unsupported URL scheme",
			value:       "file:///tmp/chisel-releases.git#abc123",
			errContains: "unsupported Chisel release Git URL scheme",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := ParseRelease(test.value)
			if test.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expected, actual)
			assert.Equal(t, test.value, actual.String())
		})
	}
}

func TestParseReleaseNamedFormTakesPrecedenceOverSameNamedDirectory(t *testing.T) {
	parent := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(parent, ubuntuRelease2404), 0o755))
	t.Chdir(parent)

	actual, err := ParseRelease(ubuntuRelease2404)
	require.NoError(t, err)
	assert.Equal(t, Release{Kind: ReleaseNamed, Location: ubuntuRelease2404}, actual)

	local, err := ParseRelease("./" + ubuntuRelease2404)
	require.NoError(t, err)
	assert.Equal(t, ReleaseLocal, local.Kind)
	assert.Equal(t, filepath.Join(parent, ubuntuRelease2404), local.Location)
}

func TestInferRelease(t *testing.T) {
	tests := []struct {
		name        string
		osRelease   string
		expected    string
		errContains string
	}{
		{
			name:      "double quoted VERSION_ID",
			osRelease: "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
			expected:  "ubuntu-24.04",
		},
		{
			name:      "single quoted VERSION_ID",
			osRelease: "VERSION_ID='22.04'\n",
			expected:  "ubuntu-22.04",
		},
		{
			name:      "unquoted VERSION_ID",
			osRelease: "VERSION_ID=20.04\n",
			expected:  "ubuntu-20.04",
		},
		{
			name:        "missing VERSION_ID",
			osRelease:   "ID=ubuntu\n",
			errContains: "does not contain VERSION_ID",
		},
		{
			name:        "duplicate VERSION_ID",
			osRelease:   "VERSION_ID=22.04\nVERSION_ID=24.04\n",
			errContains: "more than once",
		},
		{
			name:        "invalid Ubuntu version",
			osRelease:   "VERSION_ID=rolling\n",
			errContains: "does not identify a supported Ubuntu release",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := InferRelease(strings.NewReader(test.osRelease))
			if test.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, Release{Kind: ReleaseNamed, Location: test.expected}, actual)
		})
	}
}

func TestResolveRelease(t *testing.T) {
	t.Run("explicit override wins without reading os-release", func(t *testing.T) {
		actual, err := ResolveRelease(ubuntuRelease2404, errorReader{})
		require.NoError(t, err)
		assert.Equal(t, Release{Kind: ReleaseNamed, Location: ubuntuRelease2404}, actual)
	})

	t.Run("omitted override infers release", func(t *testing.T) {
		actual, err := ResolveRelease("", strings.NewReader("VERSION_ID=24.04\n"))
		require.NoError(t, err)
		assert.Equal(t, "ubuntu-24.04", actual.Location)
	})
}

func TestInferReleaseBoundsOSReleaseSize(t *testing.T) {
	_, err := InferRelease(bytes.NewReader(bytes.Repeat([]byte{'x'}, maxOSReleaseSize+1)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "os-release data exceeds 1 MiB")
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("should not be read")
}

var _ io.Reader = errorReader{}
