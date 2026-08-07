package chisel

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

const maxOSReleaseSize = 1 << 20

var namedReleasePattern = regexp.MustCompile(`^ubuntu-[0-9]{2}\.[0-9]{2}$`)

// ReleaseKind identifies how a Chisel release definition should be resolved.
type ReleaseKind string

const (
	// ReleaseNamed identifies a standard named Chisel release.
	ReleaseNamed ReleaseKind = "named"
	// ReleaseLocal identifies a release definition in a local directory.
	ReleaseLocal ReleaseKind = "local"
	// ReleaseGit identifies a release definition in a pinned Git repository.
	ReleaseGit ReleaseKind = "git"
)

// Release describes a validated Chisel release source. Location is a release
// name, canonical local directory, or Git URL without its revision fragment.
type Release struct {
	Kind     ReleaseKind
	Location string
	Revision string
}

// String reconstructs the user-facing release source representation.
func (release Release) String() string {
	if release.Kind == ReleaseGit && release.Revision != "" {
		return release.Location + "#" + release.Revision
	}
	return release.Location
}

// ParseRelease validates an explicit named, local-directory, or pinned-Git
// Chisel release override.
func ParseRelease(value string) (Release, error) {
	if value == "" {
		return Release{}, fmt.Errorf("chisel release override is empty")
	}
	if value != strings.TrimSpace(value) {
		return Release{}, fmt.Errorf("chisel release override contains leading or trailing whitespace")
	}
	if namedReleasePattern.MatchString(value) {
		return Release{Kind: ReleaseNamed, Location: value}, nil
	}
	if strings.Contains(value, "://") {
		return parseGitRelease(value)
	}

	info, err := os.Stat(value)
	if err != nil {
		if os.IsNotExist(err) {
			return Release{}, fmt.Errorf("chisel release %q is neither a standard release name, an existing local directory, nor a pinned Git URL", value)
		}
		return Release{}, fmt.Errorf("cannot inspect local Chisel release directory %q: %w", value, err)
	}
	if !info.IsDir() {
		return Release{}, fmt.Errorf("local Chisel release path %q is not a directory", value)
	}

	location, err := filepath.Abs(value)
	if err != nil {
		return Release{}, fmt.Errorf("cannot make local Chisel release path absolute: %w", err)
	}
	return Release{Kind: ReleaseLocal, Location: filepath.Clean(location)}, nil
}

// InferRelease infers a standard Chisel release from VERSION_ID in an
// /etc/os-release stream.
func InferRelease(osRelease io.Reader) (Release, error) {
	if osRelease == nil {
		return Release{}, fmt.Errorf("cannot infer Chisel release: os-release reader is nil")
	}
	data, err := io.ReadAll(io.LimitReader(osRelease, maxOSReleaseSize+1))
	if err != nil {
		return Release{}, fmt.Errorf("cannot read os-release data: %w", err)
	}
	if len(data) > maxOSReleaseSize {
		return Release{}, fmt.Errorf("cannot infer Chisel release: os-release data exceeds %d MiB", maxOSReleaseSize>>20)
	}

	versionID, err := osReleaseVersionID(data)
	if err != nil {
		return Release{}, fmt.Errorf("cannot infer Chisel release: %w", err)
	}
	name := "ubuntu-" + versionID
	if !namedReleasePattern.MatchString(name) {
		return Release{}, fmt.Errorf("VERSION_ID %q does not identify a supported Ubuntu release", versionID)
	}
	return Release{Kind: ReleaseNamed, Location: name}, nil
}

// ResolveRelease parses an explicit override when present, otherwise inferring
// a named release from os-release.
func ResolveRelease(override string, osRelease io.Reader) (Release, error) {
	if override != "" {
		return ParseRelease(override)
	}
	return InferRelease(osRelease)
}

func parseGitRelease(value string) (Release, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return Release{}, fmt.Errorf("invalid Chisel release Git URL %q: %w", value, err)
	}
	if parsed.Scheme != "https" {
		return Release{}, fmt.Errorf("unsupported Chisel release Git URL scheme %q; only public HTTPS URLs are supported", parsed.Scheme)
	}
	if parsed.Host == "" || parsed.Path == "" {
		return Release{}, fmt.Errorf("invalid Chisel release Git URL %q", value)
	}
	if parsed.User != nil {
		_, hasPassword := parsed.User.Password()
		if parsed.Scheme != "ssh" || hasPassword {
			return Release{}, fmt.Errorf("chisel release Git URL must not contain embedded credentials")
		}
	}
	if parsed.RawQuery != "" {
		return Release{}, fmt.Errorf("chisel release Git URL must not contain a query string")
	}
	if parsed.Fragment == "" {
		return Release{}, fmt.Errorf("chisel release Git URL must include a pinned commit or tag fragment")
	}
	if err := validateGitRevision(parsed.Fragment); err != nil {
		return Release{}, fmt.Errorf("invalid Chisel release Git revision %q: %w", parsed.Fragment, err)
	}

	revision := parsed.Fragment
	parsed.Fragment = ""
	return Release{Kind: ReleaseGit, Location: parsed.String(), Revision: revision}, nil
}

func validateGitRevision(revision string) error {
	if revision == "HEAD" || strings.HasPrefix(revision, "-") {
		return fmt.Errorf("revision must name a commit or tag, not a symbolic or option-like reference")
	}
	if strings.HasPrefix(revision, ".") || strings.HasSuffix(revision, ".") ||
		strings.HasPrefix(revision, "/") || strings.HasSuffix(revision, "/") ||
		strings.HasSuffix(revision, ".lock") {
		return fmt.Errorf("revision has an invalid boundary")
	}
	if strings.Contains(revision, "..") || strings.Contains(revision, "@{") ||
		strings.Contains(revision, "//") || strings.Contains(revision, "/.") {
		return fmt.Errorf("revision contains an invalid sequence")
	}
	if strings.ContainsAny(revision, " ~^:?*[\\") {
		return fmt.Errorf("revision contains a character forbidden by Git")
	}
	if strings.ContainsFunc(revision, unicode.IsControl) {
		return fmt.Errorf("revision contains a control character")
	}
	return nil
}

func osReleaseVersionID(data []byte) (string, error) {
	var versionID string
	seenVersionID := false
	for lineNumber, rawLine := range bytes.Split(data, []byte{'\n'}) {
		line := strings.TrimSpace(string(rawLine))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, rawValue, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "VERSION_ID" {
			continue
		}
		if seenVersionID {
			return "", fmt.Errorf("os-release contains VERSION_ID more than once")
		}
		seenVersionID = true
		value, err := parseOSReleaseValue(strings.TrimSpace(rawValue))
		if err != nil {
			return "", fmt.Errorf("invalid VERSION_ID on line %d: %w", lineNumber+1, err)
		}
		versionID = value
	}
	if versionID == "" {
		return "", fmt.Errorf("os-release does not contain VERSION_ID")
	}
	return versionID, nil
}

func parseOSReleaseValue(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("value is empty")
	}
	switch value[0] {
	case '"':
		parsed, err := strconv.Unquote(value)
		if err != nil {
			return "", err
		}
		return parsed, nil
	case '\'':
		if len(value) < 2 || value[len(value)-1] != '\'' {
			return "", fmt.Errorf("unterminated single-quoted value")
		}
		return value[1 : len(value)-1], nil
	default:
		if strings.ContainsFunc(value, unicode.IsSpace) {
			return "", fmt.Errorf("unquoted value contains whitespace")
		}
		return value, nil
	}
}
