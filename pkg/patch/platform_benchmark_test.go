package patch

import (
	"testing"

	ispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/project-copacetic/copacetic/pkg/types"
)

var (
	patchStringSink    string
	patchStringsSink   []string
	patchPlatformsSink []types.PatchPlatform
	patchBytesSink     []byte
)

func benchmarkPatchPlatforms() []types.PatchPlatform {
	return []types.PatchPlatform{
		{Platform: ispec.Platform{OS: "linux", Architecture: "386"}},
		{Platform: ispec.Platform{OS: "linux", Architecture: "amd64"}},
		{Platform: ispec.Platform{OS: "linux", Architecture: "arm", Variant: "v5"}},
		{Platform: ispec.Platform{OS: "linux", Architecture: "arm", Variant: "v6"}},
		{Platform: ispec.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}},
		{Platform: ispec.Platform{OS: "linux", Architecture: "arm64"}},
		{Platform: ispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}},
		{Platform: ispec.Platform{OS: "linux", Architecture: "ppc64le"}},
		{Platform: ispec.Platform{OS: "linux", Architecture: "s390x"}},
		{Platform: ispec.Platform{OS: "linux", Architecture: "riscv64"}},
	}
}

func BenchmarkArchTag(b *testing.B) {
	cases := []struct {
		base    string
		arch    string
		variant string
	}{
		{base: "patched", arch: "amd64"},
		{base: "patched", arch: "arm", variant: "v7"},
		{base: "v1.2.3-patched", arch: "arm64", variant: "v8"},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c := cases[i%len(cases)]
		patchStringSink = archTag(c.base, c.arch, c.variant)
	}
}

func BenchmarkArchTagSuffixes(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		patchStringsSink = ArchTagSuffixes()
	}
}

func BenchmarkFilterPlatforms(b *testing.B) {
	discovered := benchmarkPatchPlatforms()
	targets := []string{
		"linux/amd64",
		"linux/arm64/v8",
		"linux/arm/v7",
		"linux/s390x",
		"linux/riscv64",
		"linux/ppc64le",
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		patchPlatformsSink = filterPlatforms(discovered, targets)
	}
}

func BenchmarkNormalizeConfigForPlatform(b *testing.B) {
	config := []byte(
		`{"architecture":"amd64","config":{"Env":["PATH=/usr/bin"],` +
			`"Labels":{"org.opencontainers.image.version":"1.0.0"}},` +
			`"created":"2024-01-01T00:00:00Z",` +
			`"history":[{"created_by":"/bin/sh"}],"os":"linux",` +
			`"rootfs":{"type":"layers","diff_ids":[` +
			`"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]},` +
			`"variant":"v7"}`,
	)
	platforms := benchmarkPatchPlatforms()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := &types.PatchPlatform{Platform: platforms[i%len(platforms)].Platform}
		out, err := normalizeConfigForPlatform(config, p)
		if err != nil {
			b.Fatal(err)
		}
		patchBytesSink = out
	}
}
