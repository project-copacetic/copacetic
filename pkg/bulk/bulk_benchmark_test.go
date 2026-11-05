package bulk

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	log "github.com/sirupsen/logrus"
)

func withBenchmarkLogger(b *testing.B) {
	b.Helper()
	origOut := log.StandardLogger().Out
	origLevel := log.GetLevel()
	log.SetOutput(io.Discard)
	log.SetLevel(log.InfoLevel)
	b.Cleanup(func() {
		log.SetOutput(origOut)
		log.SetLevel(origLevel)
	})
}

func benchmarkSemverTags(count int) []string {
	tags := make([]string, 0, count+count/10+3)
	for i := 0; i < count; i++ {
		tags = append(tags, fmt.Sprintf("1.%d.%d", i/100, i%100))
	}
	for i := 0; i < count/10; i++ {
		tags = append(tags, fmt.Sprintf("dev-%d", i))
	}
	tags = append(tags, "latest", "1.999.0-alpha", "1.500.0-alpine")
	return tags
}

func benchmarkPatchTags(baseTag string, count int) []string {
	tags := make([]string, 0, count*2+32)
	for i := 0; i < count; i++ {
		tags = append(tags,
			fmt.Sprintf("unrelated-%d", i),
			fmt.Sprintf("%s-%d", baseTag, i+10000),
		)
	}
	tags = append(tags,
		baseTag+"-386",
		baseTag+"-amd64",
		baseTag+"-arm-v7",
		baseTag+"-arm64",
		baseTag+"-not-a-number",
	)
	return tags
}

func BenchmarkFindTagsByPattern(b *testing.B) {
	withBenchmarkLogger(b)

	repo, err := name.NewRepository("example.com/team/app")
	if err != nil {
		b.Fatal(err)
	}
	tags := benchmarkSemverTags(10000)
	spec := &ImageSpec{
		Name: "app",
		Tags: TagStrategy{
			Strategy:        StrategyPattern,
			Pattern:         `^1\.[0-9]+\.[0-9]+$`,
			MaxTags:         250,
			Exclude:         []string{"1.10.0", "1.20.0", "1.30.0", "1.40.0"},
			compiledPattern: regexp.MustCompile(`^1\.[0-9]+\.[0-9]+$`),
		},
	}
	originalLister := listAllTags
	listAllTags = mockTagLister(tags, nil)
	b.Cleanup(func() { listAllTags = originalLister })

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := findTagsByPattern(repo, spec)
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != spec.Tags.MaxTags {
			b.Fatalf("expected %d tags, got %d", spec.Tags.MaxTags, len(got))
		}
	}
}

func BenchmarkFindTagsByLatest(b *testing.B) {
	withBenchmarkLogger(b)

	repo, err := name.NewRepository("example.com/team/app")
	if err != nil {
		b.Fatal(err)
	}
	tags := benchmarkSemverTags(10000)
	spec := &ImageSpec{Name: "app"}
	originalLister := listAllTags
	listAllTags = mockTagLister(tags, nil)
	b.Cleanup(func() { listAllTags = originalLister })

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := findTagsByLatest(repo, spec)
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != 1 || got[0] != "1.99.99" {
			b.Fatalf("unexpected latest tag: %v", got)
		}
	}
}

func BenchmarkDiscoverExistingPatchTags(b *testing.B) {
	withBenchmarkLogger(b)

	baseTag := "1.25.3-patched"
	tags := benchmarkPatchTags(baseTag, 10000)
	originalLister := listAllTags
	listAllTags = mockTagLister(tags, nil)
	b.Cleanup(func() { listAllTags = originalLister })

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := discoverExistingPatchTags("example.com/team/app", baseTag)
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != 10000 {
			b.Fatalf("expected 10000 tags, got %d", len(got))
		}
	}
}

func BenchmarkBuildReportIndex(b *testing.B) {
	withBenchmarkLogger(b)

	dir := b.TempDir()
	padding := strings.Repeat("x", 64*1024)
	for i := 0; i < 200; i++ {
		content := fmt.Sprintf(
			`{"SchemaVersion":2,"ArtifactName":"example.com/team/app:%d",`+
				`"Results":[{"Target":"os-pkgs","Class":"os-pkgs",`+
				`"Type":"debian","Vulnerabilities":[],"Padding":"%s"}]}`,
			i,
			padding,
		)
		if err := writeBenchmarkFile(filepath.Join(dir, fmt.Sprintf("report-%04d.json", i)), content); err != nil {
			b.Fatal(err)
		}
	}
	if err := writeBenchmarkFile(filepath.Join(dir, "ignore.txt"), "not json"); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		idx := buildReportIndex(dir)
		if len(idx.refs) != 200 {
			b.Fatalf("expected 200 indexed refs, got %d", len(idx.refs))
		}
	}
}

func BenchmarkReportIndexLookup(b *testing.B) {
	withBenchmarkLogger(b)

	idx := &reportIndex{refs: make(map[string]string, 10000)}
	for i := 0; i < 10000; i++ {
		idx.refs[fmt.Sprintf("example.com/team/app:%d", i)] = fmt.Sprintf("/reports/%d.json", i)
	}
	lookupRef := "example.com/team/app:9999"

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		path, ok := idx.lookup(lookupRef)
		if !ok || path == "" {
			b.Fatal("expected lookup hit")
		}
	}
}

func BenchmarkResolveTargetTagDefault(b *testing.B) {
	target := TargetSpec{}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := resolveTargetTag(target, "1.25.3")
		if err != nil {
			b.Fatal(err)
		}
		if got != "1.25.3-patched" {
			b.Fatalf("unexpected target tag: %s", got)
		}
	}
}

func BenchmarkResolveTargetTagTemplate(b *testing.B) {
	target := TargetSpec{Tag: "{{ .SourceTag }}-fixed"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := resolveTargetTag(target, "1.25.3")
		if err != nil {
			b.Fatal(err)
		}
		if got != "1.25.3-fixed" {
			b.Fatalf("unexpected target tag: %s", got)
		}
	}
}

func BenchmarkPrintSummary(b *testing.B) {
	withBenchmarkLogger(b)

	results := make([]patchJobStatus, 1000)
	for i := range results {
		results[i] = patchJobStatus{
			Name:   fmt.Sprintf("image-%04d", i%50),
			Source: fmt.Sprintf("example.com/team/app:%04d", i),
			Target: fmt.Sprintf("example.com/patched/app:%04d-patched", i),
			Status: "Patched",
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		printSummary(results)
	}
}

func writeBenchmarkFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
