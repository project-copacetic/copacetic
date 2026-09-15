// SPDX-License-Identifier: Apache-2.0

package chisel

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	realImageOptInEnv = "COPA_CHISEL_INSPECT_REAL_IMAGES"
	maxManifestSize   = 64 << 20
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type fixtureCatalog struct {
	SchemaVersion int                `json:"schemaVersion"`
	VerifiedAt    string             `json:"verifiedAt"`
	Images        []realImageFixture `json:"images"`
}

type realImageFixture struct {
	ID                    string                `json:"id"`
	Layout                string                `json:"layout"`
	TaggedReference       string                `json:"taggedReference"`
	Reference             string                `json:"reference"`
	InferredChiselRelease string                `json:"inferredChiselRelease"`
	Index                 imageIndexFixture     `json:"index"`
	ExpectedConfig        imageConfigFixture    `json:"expectedConfig"`
	Observations          []platformObservation `json:"observations"`
}

type imageIndexFixture struct {
	Digest    string                  `json:"digest"`
	MediaType string                  `json:"mediaType"`
	Platforms []platformDigestFixture `json:"platforms"`
}

type platformDigestFixture struct {
	Platform string `json:"platform"`
	Digest   string `json:"digest"`
}

type imageConfigFixture struct {
	User       string   `json:"user"`
	WorkingDir string   `json:"workingDir"`
	Entrypoint []string `json:"entrypoint"`
	Cmd        []string `json:"cmd"`
}

type platformObservation struct {
	Platform                   string                 `json:"platform"`
	ManifestDigest             string                 `json:"manifestDigest"`
	OSRelease                  osReleaseFixture       `json:"osRelease"`
	Paths                      imagePathsFixture      `json:"paths"`
	MissingRequiredTargetTools []string               `json:"missingRequiredTargetTools"`
	DPKGStatus                 *dpkgStatusFixture     `json:"dpkgStatus,omitempty"`
	ChiselManifest             *chiselManifestFixture `json:"chiselManifest,omitempty"`
}

type osReleaseFixture struct {
	ID        string `json:"id"`
	VersionID string `json:"versionId"`
}

type imagePathsFixture struct {
	DPKGStatus          bool `json:"dpkgStatus"`
	DPKGStatusDirectory bool `json:"dpkgStatusDirectory"`
	ChiselManifest      bool `json:"chiselManifest"`
}

type dpkgStatusFixture struct {
	SHA256            string `json:"sha256"`
	Bytes             int    `json:"bytes"`
	PackageParagraphs int    `json:"packageParagraphs"`
	StatusFields      int    `json:"statusFields"`
}

type chiselManifestFixture struct {
	SHA256                 string `json:"sha256"`
	CompressedBytes        int    `json:"compressedBytes"`
	JSONWall               string `json:"jsonwall"`
	Schema                 string `json:"schema"`
	RecordsIncludingHeader int    `json:"recordsIncludingHeader"`
	Packages               int    `json:"packages"`
	Slices                 int    `json:"slices"`
	Contents               int    `json:"contents"`
	Paths                  int    `json:"paths"`
}

type extractedRoot struct {
	entries   map[string]struct{}
	files     map[string][]byte
	toolPaths map[string][]string
}

type manifestSummary struct {
	JSONWall string
	Schema   string
	Count    int
	Records  int
	Packages int
	Slices   int
	Contents int
	Paths    int
}

func TestRealImageFixtureMetadata(t *testing.T) {
	catalog := loadCatalog(t)
	if catalog.SchemaVersion != 1 {
		t.Fatalf("unexpected fixture schema version %d", catalog.SchemaVersion)
	}
	if _, err := time.Parse(time.DateOnly, catalog.VerifiedAt); err != nil {
		t.Fatalf("invalid verifiedAt %q: %v", catalog.VerifiedAt, err)
	}
	if len(catalog.Images) != 2 {
		t.Fatalf("expected fixtures for exactly two Chiseled layouts, got %d", len(catalog.Images))
	}

	seenIDs := make(map[string]struct{}, len(catalog.Images))
	seenLayouts := make(map[string]struct{}, len(catalog.Images))
	for _, image := range catalog.Images {
		if image.ID == "" {
			t.Fatal("fixture has an empty id")
		}
		if _, ok := seenIDs[image.ID]; ok {
			t.Fatalf("duplicate fixture id %q", image.ID)
		}
		seenIDs[image.ID] = struct{}{}
		seenLayouts[image.Layout] = struct{}{}

		if !digestPattern.MatchString(image.Index.Digest) {
			t.Fatalf("fixture %q has invalid index digest %q", image.ID, image.Index.Digest)
		}
		if !strings.HasSuffix(image.Reference, "@"+image.Index.Digest) {
			t.Fatalf("fixture %q reference is not pinned to index digest %q", image.ID, image.Index.Digest)
		}
		if strings.Contains(image.TaggedReference, "@") {
			t.Fatalf("fixture %q taggedReference unexpectedly contains a digest", image.ID)
		}
		if !strings.HasPrefix(image.InferredChiselRelease, "ubuntu-") {
			t.Fatalf("fixture %q has invalid inferred release %q", image.ID, image.InferredChiselRelease)
		}

		platformDigests := make(map[string]string, len(image.Index.Platforms))
		for _, platform := range image.Index.Platforms {
			if platform.Platform == "" || !digestPattern.MatchString(platform.Digest) {
				t.Fatalf("fixture %q has invalid platform descriptor %+v", image.ID, platform)
			}
			if _, ok := platformDigests[platform.Platform]; ok {
				t.Fatalf("fixture %q repeats platform %q", image.ID, platform.Platform)
			}
			platformDigests[platform.Platform] = platform.Digest
		}

		for _, observation := range image.Observations {
			descriptorDigest, ok := platformDigests[observation.Platform]
			if !ok {
				t.Fatalf("fixture %q observes platform %q missing from its index", image.ID, observation.Platform)
			}
			if observation.ManifestDigest != descriptorDigest {
				t.Fatalf("fixture %q platform %q digest mismatch: %s != %s", image.ID, observation.Platform, observation.ManifestDigest, descriptorDigest)
			}
			assertMissingToolSet(t, image.ID, observation.MissingRequiredTargetTools)

			switch image.Layout {
			case "external-full-status":
				if observation.DPKGStatus == nil || observation.ChiselManifest != nil {
					t.Fatalf("fixture %q platform %q has inconsistent full-status metadata", image.ID, observation.Platform)
				}
				if !observation.Paths.DPKGStatus || observation.Paths.DPKGStatusDirectory || observation.Paths.ChiselManifest {
					t.Fatalf("fixture %q platform %q has inconsistent full-status paths", image.ID, observation.Platform)
				}
				if observation.DPKGStatus.StatusFields != 0 {
					t.Fatalf("fixture %q platform %q should preserve the real image's Status-field-free control paragraphs", image.ID, observation.Platform)
				}
			case "native-chisel":
				if observation.DPKGStatus != nil || observation.ChiselManifest == nil {
					t.Fatalf("fixture %q platform %q has inconsistent native-manifest metadata", image.ID, observation.Platform)
				}
				if observation.Paths.DPKGStatus || observation.Paths.DPKGStatusDirectory || !observation.Paths.ChiselManifest {
					t.Fatalf("fixture %q platform %q has inconsistent native-manifest paths", image.ID, observation.Platform)
				}
			default:
				t.Fatalf("fixture %q has unknown layout %q", image.ID, image.Layout)
			}
		}
	}

	for _, layout := range []string{"external-full-status", "native-chisel"} {
		if _, ok := seenLayouts[layout]; !ok {
			t.Fatalf("missing fixture for layout %q", layout)
		}
	}
}

func TestSyntheticManifestFixture(t *testing.T) {
	fixtureDir := filepath.Join("fixtures", "manifest-schema-1.0")
	compressed := readFile(t, filepath.Join(fixtureDir, "manifest.wall"))
	wantJSONWall := readFile(t, filepath.Join(fixtureDir, "manifest.jsonwall"))

	decoder, err := zstd.NewReader(
		bytes.NewReader(compressed),
		zstd.WithDecoderMaxWindow(maxManifestSize),
		zstd.WithDecoderMaxMemory(maxManifestSize+1),
	)
	if err != nil {
		t.Fatalf("open compressed fixture: %v", err)
	}
	decompressed, err := io.ReadAll(io.LimitReader(decoder, maxManifestSize+1))
	decoder.Close()
	if err != nil {
		t.Fatalf("decompress fixture: %v", err)
	}
	if len(decompressed) > maxManifestSize {
		t.Fatalf("decompressed fixture exceeds %d bytes", maxManifestSize)
	}
	if !bytes.Equal(decompressed, wantJSONWall) {
		t.Fatal("compressed manifest does not match manifest.jsonwall")
	}

	var expected struct {
		JSONWall               string   `json:"jsonwall"`
		Schema                 string   `json:"schema"`
		RecordsIncludingHeader int      `json:"recordsIncludingHeader"`
		Packages               int      `json:"packages"`
		Slices                 int      `json:"slices"`
		Contents               int      `json:"contents"`
		Paths                  int      `json:"paths"`
		OwnedPaths             []string `json:"ownedPaths"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(fixtureDir, "expected.json")), &expected); err != nil {
		t.Fatalf("decode expected manifest metadata: %v", err)
	}

	summary, ownedPaths := summarizeManifest(t, decompressed)
	if summary.JSONWall != expected.JSONWall || summary.Schema != expected.Schema ||
		summary.Records != expected.RecordsIncludingHeader || summary.Count != expected.RecordsIncludingHeader ||
		summary.Packages != expected.Packages || summary.Slices != expected.Slices ||
		summary.Contents != expected.Contents || summary.Paths != expected.Paths {
		t.Fatalf("manifest summary mismatch: got %+v, expected %+v", summary, expected)
	}
	slices.Sort(ownedPaths)
	slices.Sort(expected.OwnedPaths)
	if !slices.Equal(ownedPaths, expected.OwnedPaths) {
		t.Fatalf("owned paths mismatch: got %v, expected %v", ownedPaths, expected.OwnedPaths)
	}

	data := readFile(t, filepath.Join(fixtureDir, "data.txt"))
	wantDigest := ""
	scanner := bufio.NewScanner(bytes.NewReader(decompressed))
	for scanner.Scan() {
		var record struct {
			Kind   string `json:"kind"`
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("decode fixture record: %v", err)
		}
		if record.Kind == "path" && record.Path == "/opt/copa-fixture/data.txt" {
			wantDigest = record.SHA256
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan fixture records: %v", err)
	}
	if got := sha256Hex(data); got != wantDigest {
		t.Fatalf("data.txt digest is %s, expected %s", got, wantDigest)
	}
}

// TestInspectPinnedRealImages intentionally does not run during ordinary
// integration tests. Opt in when refreshing fixtures or before enabling real
// image smoke coverage. Missing registry tooling causes a skip rather than a
// failure so this package remains safe in lightweight CI jobs.
func TestInspectPinnedRealImages(t *testing.T) {
	if os.Getenv(realImageOptInEnv) != "1" {
		t.Skipf("set %s=1 to inspect pinned registry images", realImageOptInEnv)
	}
	crane, err := exec.LookPath("crane")
	if err != nil {
		t.Skip("crane is not installed")
	}

	catalog := loadCatalog(t)
	for imageIndex := range catalog.Images {
		image := &catalog.Images[imageIndex]
		t.Run(image.ID, func(t *testing.T) {
			if got := strings.TrimSpace(run(t, crane, "digest", image.Reference)); got != image.Index.Digest {
				t.Fatalf("index digest changed: got %s, expected %s", got, image.Index.Digest)
			}

			for observationIndex := range image.Observations {
				observation := &image.Observations[observationIndex]
				t.Run(strings.ReplaceAll(observation.Platform, "/", "-"), func(t *testing.T) {
					if got := strings.TrimSpace(run(t, crane, "digest", "--platform", observation.Platform, image.Reference)); got != observation.ManifestDigest {
						t.Fatalf("platform digest changed: got %s, expected %s", got, observation.ManifestDigest)
					}

					var config struct {
						Config imageConfigFixture `json:"config"`
					}
					if err := json.Unmarshal([]byte(run(t, crane, "config", "--platform", observation.Platform, image.Reference)), &config); err != nil {
						t.Fatalf("decode image config: %v", err)
					}
					if !equalConfig(&config.Config, &image.ExpectedConfig) {
						t.Fatalf("image config changed: got %+v, expected %+v", config.Config, image.ExpectedConfig)
					}

					tarPath := filepath.Join(t.TempDir(), "rootfs.tar")
					run(t, crane, "export", "--platform", observation.Platform, image.Reference, tarPath)
					root := inspectRootfsTar(t, tarPath)
					verifyObservation(t, root, observation)
				})
			}
		})
	}
}

func loadCatalog(t *testing.T) fixtureCatalog {
	t.Helper()
	var catalog fixtureCatalog
	if err := json.Unmarshal(readFile(t, filepath.Join("fixtures", "real-images.json")), &catalog); err != nil {
		t.Fatalf("decode real image fixtures: %v", err)
	}
	return catalog
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return contents
}

func assertMissingToolSet(t *testing.T, imageID string, got []string) {
	t.Helper()
	want := []string{"apt-get", "apt-mark", "dpkg", "grep", "sh", "tee"}
	got = slices.Clone(got)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("fixture %q missing tool set is %v, expected %v", imageID, got, want)
	}
}

func equalConfig(got, want *imageConfigFixture) bool {
	return got.User == want.User && got.WorkingDir == want.WorkingDir &&
		slices.Equal(got.Entrypoint, want.Entrypoint) && slices.Equal(got.Cmd, want.Cmd)
}

func run(t *testing.T, command string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", command, strings.Join(args, " "), err, output)
	}
	return string(output)
}

func inspectRootfsTar(t *testing.T, tarPath string) extractedRoot {
	t.Helper()
	file, err := os.Open(tarPath)
	if err != nil {
		t.Fatalf("open exported rootfs: %v", err)
	}
	defer file.Close()

	root := extractedRoot{
		entries: make(map[string]struct{}),
		files:   make(map[string][]byte),
		toolPaths: map[string][]string{
			"apt-get":  {"usr/bin/apt-get"},
			"apt-mark": {"usr/bin/apt-mark"},
			"dpkg":     {"usr/bin/dpkg"},
			"sh":       {"bin/sh", "usr/bin/sh"},
			"grep":     {"bin/grep", "usr/bin/grep"},
			"tee":      {"bin/tee", "usr/bin/tee"},
		},
	}
	wantedFiles := map[string]struct{}{
		"var/lib/dpkg/status":          {},
		"var/lib/chisel/manifest.wall": {},
		"usr/lib/os-release":           {},
	}

	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read exported rootfs: %v", err)
		}
		name := path.Clean(strings.TrimPrefix(header.Name, "./"))
		root.entries[name] = struct{}{}
		if _, ok := wantedFiles[name]; !ok || !header.FileInfo().Mode().IsRegular() {
			continue
		}
		limit := int64(maxManifestSize + 1)
		if name == "var/lib/dpkg/status" || name == "usr/lib/os-release" {
			limit = 4 << 20
		}
		contents, err := io.ReadAll(io.LimitReader(reader, limit))
		if err != nil {
			t.Fatalf("read %s from exported rootfs: %v", name, err)
		}
		if int64(len(contents)) == limit {
			t.Fatalf("exported file %s exceeds inspection limit", name)
		}
		root.files[name] = contents
	}
	return root
}

func verifyObservation(t *testing.T, root extractedRoot, observation *platformObservation) {
	t.Helper()
	assertPathState(t, root, "var/lib/dpkg/status", observation.Paths.DPKGStatus)
	assertPathPrefixState(t, root, "var/lib/dpkg/status.d", observation.Paths.DPKGStatusDirectory)
	assertPathState(t, root, "var/lib/chisel/manifest.wall", observation.Paths.ChiselManifest)

	for _, tool := range observation.MissingRequiredTargetTools {
		for _, toolPath := range root.toolPaths[tool] {
			if _, ok := root.entries[toolPath]; ok {
				t.Fatalf("required target tool %q unexpectedly exists at /%s", tool, toolPath)
			}
		}
	}

	osRelease := parseOSRelease(t, root.files["usr/lib/os-release"])
	if osRelease.ID != observation.OSRelease.ID || osRelease.VersionID != observation.OSRelease.VersionID {
		t.Fatalf("os-release mismatch: got %+v, expected %+v", osRelease, observation.OSRelease)
	}

	if observation.DPKGStatus != nil {
		contents := root.files["var/lib/dpkg/status"]
		paragraphs, statusFields := summarizeDPKGStatus(contents)
		got := dpkgStatusFixture{
			SHA256:            sha256Hex(contents),
			Bytes:             len(contents),
			PackageParagraphs: paragraphs,
			StatusFields:      statusFields,
		}
		if got != *observation.DPKGStatus {
			t.Fatalf("dpkg status metadata changed: got %+v, expected %+v", got, *observation.DPKGStatus)
		}
	}

	if observation.ChiselManifest != nil {
		contents := root.files["var/lib/chisel/manifest.wall"]
		got := summarizeCompressedManifest(t, contents)
		want := observation.ChiselManifest
		if sha256Hex(contents) != want.SHA256 || len(contents) != want.CompressedBytes ||
			got.JSONWall != want.JSONWall || got.Schema != want.Schema || got.Count != want.RecordsIncludingHeader ||
			got.Records != want.RecordsIncludingHeader || got.Packages != want.Packages || got.Slices != want.Slices ||
			got.Contents != want.Contents || got.Paths != want.Paths {
			t.Fatalf("Chisel manifest metadata changed: sha256=%s bytes=%d summary=%+v expected=%+v", sha256Hex(contents), len(contents), got, *want)
		}
	}
}

func assertPathState(t *testing.T, root extractedRoot, name string, want bool) {
	t.Helper()
	_, present := root.entries[name]
	if present != want {
		t.Fatalf("path /%s presence is %t, expected %t", name, present, want)
	}
}

func assertPathPrefixState(t *testing.T, root extractedRoot, name string, want bool) {
	t.Helper()
	present := false
	for entry := range root.entries {
		if entry == name || strings.HasPrefix(entry, name+"/") {
			present = true
			break
		}
	}
	if present != want {
		t.Fatalf("path /%s presence is %t, expected %t", name, present, want)
	}
}

func parseOSRelease(t *testing.T, contents []byte) osReleaseFixture {
	t.Helper()
	if len(contents) == 0 {
		t.Fatal("exported rootfs has no /usr/lib/os-release")
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(contents), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return osReleaseFixture{ID: values["ID"], VersionID: values["VERSION_ID"]}
}

func summarizeDPKGStatus(contents []byte) (paragraphs, statusFields int) {
	for _, paragraph := range strings.Split(strings.TrimSpace(strings.ReplaceAll(string(contents), "\r\n", "\n")), "\n\n") {
		hasPackage := false
		hasVersion := false
		for _, line := range strings.Split(paragraph, "\n") {
			switch {
			case strings.HasPrefix(line, "Package:"):
				hasPackage = true
			case strings.HasPrefix(line, "Version:"):
				hasVersion = true
			case strings.HasPrefix(line, "Status:"):
				statusFields++
			}
		}
		if hasPackage && hasVersion {
			paragraphs++
		}
	}
	return paragraphs, statusFields
}

func summarizeCompressedManifest(t *testing.T, contents []byte) manifestSummary {
	t.Helper()
	decoder, err := zstd.NewReader(
		bytes.NewReader(contents),
		zstd.WithDecoderMaxWindow(maxManifestSize),
		zstd.WithDecoderMaxMemory(maxManifestSize+1),
	)
	if err != nil {
		t.Fatalf("open Chisel manifest: %v", err)
	}
	decompressed, err := io.ReadAll(io.LimitReader(decoder, maxManifestSize+1))
	decoder.Close()
	if err != nil {
		t.Fatalf("decompress Chisel manifest: %v", err)
	}
	if len(decompressed) > maxManifestSize {
		t.Fatalf("decompressed Chisel manifest exceeds %d bytes", maxManifestSize)
	}
	summary, _ := summarizeManifest(t, decompressed)
	return summary
}

func summarizeManifest(t *testing.T, contents []byte) (manifestSummary, []string) {
	t.Helper()
	var summary manifestSummary
	var ownedPaths []string
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	for scanner.Scan() {
		var record struct {
			JSONWall string `json:"jsonwall"`
			Schema   string `json:"schema"`
			Count    int    `json:"count"`
			Kind     string `json:"kind"`
			Path     string `json:"path"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("decode Chisel manifest record %d: %v", summary.Records+1, err)
		}
		summary.Records++
		if summary.Records == 1 {
			summary.JSONWall = record.JSONWall
			summary.Schema = record.Schema
			summary.Count = record.Count
		}
		switch record.Kind {
		case "package":
			summary.Packages++
		case "slice":
			summary.Slices++
		case "content":
			summary.Contents++
		case "path":
			summary.Paths++
			ownedPaths = append(ownedPaths, record.Path)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan Chisel manifest: %v", err)
	}
	return summary, ownedPaths
}

func sha256Hex(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}
