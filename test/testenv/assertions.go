package testenv

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// AssertFileExists asserts that a file exists at the given path.
func (r *RefInspector) AssertFileExists(t *testing.T, path string) {
	t.Helper()
	if !r.FileExists(path) {
		t.Errorf("expected file %s to exist, but it does not", path)
	}
}

// AssertFileNotExists asserts that a file does not exist at the given path.
func (r *RefInspector) AssertFileNotExists(t *testing.T, path string) {
	t.Helper()
	if r.FileExists(path) {
		t.Errorf("expected file %s to not exist, but it does", path)
	}
}

// AssertDirExists asserts that a directory exists at the given path.
func (r *RefInspector) AssertDirExists(t *testing.T, path string) {
	t.Helper()
	if !r.DirExists(path) {
		t.Errorf("expected directory %s to exist, but it does not", path)
	}
}

// AssertFileContains asserts that a file contains the given substring.
func (r *RefInspector) AssertFileContains(t *testing.T, path, substr string) {
	t.Helper()
	content, err := r.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", path, err)
	}
	if !strings.Contains(string(content), substr) {
		t.Errorf("file %s does not contain expected substring %q\nContent:\n%s", path, substr, truncateForError(content))
	}
}

// AssertFileNotContains asserts that a file does not contain the given substring.
func (r *RefInspector) AssertFileNotContains(t *testing.T, path, substr string) {
	t.Helper()
	content, err := r.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", path, err)
	}
	if strings.Contains(string(content), substr) {
		t.Errorf("file %s unexpectedly contains substring %q", path, substr)
	}
}

// AssertFileEquals asserts that a file's content exactly matches the expected bytes.
func (r *RefInspector) AssertFileEquals(t *testing.T, path string, expected []byte) {
	t.Helper()
	content, err := r.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", path, err)
	}
	if !bytes.Equal(content, expected) {
		t.Errorf("file %s content mismatch\nExpected:\n%s\nActual:\n%s",
			path, truncateForError(expected), truncateForError(content))
	}
}

// AssertFileMatches asserts that a file's content matches the given regex pattern.
func (r *RefInspector) AssertFileMatches(t *testing.T, path, pattern string) {
	t.Helper()
	content, err := r.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", path, err)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("invalid regex pattern %q: %v", pattern, err)
	}
	if !re.Match(content) {
		t.Errorf("file %s does not match pattern %q\nContent:\n%s", path, pattern, truncateForError(content))
	}
}

// AssertSymlinkTarget asserts that a symlink points to the expected target.
func (r *RefInspector) AssertSymlinkTarget(t *testing.T, path, expectedTarget string) {
	t.Helper()
	target, err := r.ReadSymlink(path)
	if err != nil {
		t.Fatalf("failed to read symlink %s: %v", path, err)
	}
	if target != expectedTarget {
		t.Errorf("symlink %s target mismatch: expected %q, got %q", path, expectedTarget, target)
	}
}

// AssertDirContainsFile asserts that a directory contains a file with the given name.
func (r *RefInspector) AssertDirContainsFile(t *testing.T, dirPath, fileName string) {
	t.Helper()
	entries, err := r.ReadDir(dirPath)
	if err != nil {
		t.Fatalf("failed to read directory %s: %v", dirPath, err)
	}
	for _, entry := range entries {
		if entry.Path == fileName {
			return
		}
	}
	t.Errorf("directory %s does not contain file %q", dirPath, fileName)
}

// AssertDebPackageVersion asserts that a Debian package is installed at the specified version.
// It reads /var/lib/dpkg/status to check the package version.
func (r *RefInspector) AssertDebPackageVersion(t *testing.T, pkgName, expectedVersion string) {
	t.Helper()
	content, err := r.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		t.Fatalf("failed to read /var/lib/dpkg/status: %v", err)
	}

	// Parse dpkg status file to find the package
	// Format:
	// Package: pkgname
	// Version: version
	// ...
	// (blank line)
	statusStr := string(content)
	pkgIndex := strings.Index(statusStr, "Package: "+pkgName+"\n")
	if pkgIndex == -1 {
		t.Errorf("package %s not found in /var/lib/dpkg/status", pkgName)
		return
	}

	// Find the version line after the package line
	pkgSection := statusStr[pkgIndex:]
	endIndex := strings.Index(pkgSection, "\n\n")
	if endIndex != -1 {
		pkgSection = pkgSection[:endIndex]
	}

	versionPrefix := "Version: "
	versionIndex := strings.Index(pkgSection, versionPrefix)
	if versionIndex == -1 {
		t.Errorf("version not found for package %s", pkgName)
		return
	}

	versionLine := pkgSection[versionIndex+len(versionPrefix):]
	endOfVersion := strings.Index(versionLine, "\n")
	if endOfVersion != -1 {
		versionLine = versionLine[:endOfVersion]
	}

	if versionLine != expectedVersion {
		t.Errorf("package %s version mismatch: expected %q, got %q", pkgName, expectedVersion, versionLine)
	}
}

// AssertApkPackageVersion asserts that an Alpine package is installed at the specified version.
// It reads /lib/apk/db/installed to check the package version.
func (r *RefInspector) AssertApkPackageVersion(t *testing.T, pkgName, expectedVersion string) {
	t.Helper()
	content, err := r.ReadFile("/lib/apk/db/installed")
	if err != nil {
		t.Fatalf("failed to read /lib/apk/db/installed: %v", err)
	}

	// APK installed format:
	// P:pkgname
	// V:version
	// ...
	// (blank line)
	statusStr := string(content)
	pkgIndex := strings.Index(statusStr, "P:"+pkgName+"\n")
	if pkgIndex == -1 {
		t.Errorf("package %s not found in /lib/apk/db/installed", pkgName)
		return
	}

	// Find the version line after the package line
	pkgSection := statusStr[pkgIndex:]
	endIndex := strings.Index(pkgSection, "\n\n")
	if endIndex != -1 {
		pkgSection = pkgSection[:endIndex]
	}

	versionIndex := strings.Index(pkgSection, "V:")
	if versionIndex == -1 {
		t.Errorf("version not found for package %s", pkgName)
		return
	}

	versionLine := pkgSection[versionIndex+2:]
	endOfVersion := strings.Index(versionLine, "\n")
	if endOfVersion != -1 {
		versionLine = versionLine[:endOfVersion]
	}

	if versionLine != expectedVersion {
		t.Errorf("package %s version mismatch: expected %q, got %q", pkgName, expectedVersion, versionLine)
	}
}

// AssertRpmPackageVersion asserts that an RPM package is installed at the specified version.
// It looks for the package in the RPM database files.
func (r *RefInspector) AssertRpmPackageVersion(t *testing.T, pkgName, expectedVersion string) {
	t.Helper()

	// Check for RPM manifest files that Copa might create
	// These are typically at /var/lib/rpmmanifest/container-manifest-2
	rpmManifestPaths := []string{
		"/var/lib/rpmmanifest/container-manifest-2",
		"/var/lib/rpmmanifest/container-manifest-1",
	}

	for _, path := range rpmManifestPaths {
		content, err := r.ReadFile(path)
		if err != nil {
			continue
		}

		// RPM manifest format: name\tversion-release\t...
		// or name version-release ... (space separated)
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == pkgName {
				// Check if version matches (might include release suffix)
				if strings.HasPrefix(fields[1], expectedVersion) || fields[1] == expectedVersion {
					return // Found and version matches
				}
				t.Errorf("package %s version mismatch: expected %q, got %q", pkgName, expectedVersion, fields[1])
				return
			}
		}
	}

	t.Errorf("package %s not found in RPM manifest files", pkgName)
}

// AssertPackageVersion is a generic helper that detects the package manager type
// and calls the appropriate assertion function.
func (r *RefInspector) AssertPackageVersion(t *testing.T, pkgType, pkgName, expectedVersion string) {
	t.Helper()
	switch pkgType {
	case "deb", "dpkg":
		r.AssertDebPackageVersion(t, pkgName, expectedVersion)
	case "apk":
		r.AssertApkPackageVersion(t, pkgName, expectedVersion)
	case "rpm":
		r.AssertRpmPackageVersion(t, pkgName, expectedVersion)
	default:
		t.Fatalf("unknown package type: %s (expected deb, apk, or rpm)", pkgType)
	}
}

// truncateForError truncates content for error messages to avoid overwhelming output.
func truncateForError(content []byte) string {
	const maxLen = 500
	if len(content) > maxLen {
		return string(content[:maxLen]) + "\n... (truncated)"
	}
	return string(content)
}
