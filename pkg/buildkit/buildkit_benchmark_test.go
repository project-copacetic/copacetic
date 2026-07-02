package buildkit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

var (
	buildkitDescriptorSink *remote.Descriptor
	buildkitStringSink     string
)

func benchmarkRawIndexManifest(tb testing.TB, manifests int) []byte {
	tb.Helper()

	type platform struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant,omitempty"`
	}
	type manifest struct {
		Digest    string   `json:"digest"`
		MediaType string   `json:"mediaType"`
		Size      int64    `json:"size"`
		Platform  platform `json:"platform"`
	}
	raw := struct {
		SchemaVersion int        `json:"schemaVersion"`
		MediaType     string     `json:"mediaType"`
		Manifests     []manifest `json:"manifests"`
	}{
		SchemaVersion: 2,
		MediaType:     string(v1types.DockerManifestList),
		Manifests:     make([]manifest, 0, manifests),
	}

	for i := 0; i < manifests; i++ {
		digestHex := fmt.Sprintf("%064x", i+1)
		raw.Manifests = append(raw.Manifests, manifest{
			Digest:    "sha256:" + digestHex,
			MediaType: string(v1types.DockerManifestSchema2),
			Size:      int64(1024 + i),
			Platform: platform{
				OS:           "linux",
				Architecture: "amd64",
				Variant:      fmt.Sprintf("v%d", i),
			},
		})
	}

	b, err := json.Marshal(raw)
	require.NoError(tb, err)
	return b
}

func TestDescriptorFromRawManifest(t *testing.T) {
	rawManifest := benchmarkRawIndexManifest(t, 4)
	desc, err := descriptorFromRawManifest("registry.example.com/acme/app:latest", rawManifest)
	require.NoError(t, err)
	require.Equal(t, v1types.DockerManifestList, desc.MediaType)
	require.Equal(t, int64(len(rawManifest)), desc.Size)
	require.Equal(t, rawManifest, desc.Manifest)

	sum := sha256.Sum256(rawManifest)
	require.Equal(t, hex.EncodeToString(sum[:]), desc.Digest.Hex)
}

func TestDescriptorFromRawManifestSinglePlatformSemantics(t *testing.T) {
	_, err := descriptorFromRawManifest("registry.example.com/acme/app:latest", []byte(`{"schemaVersion":2}`))
	require.EqualError(t, err, "single-platform image")

	_, err = descriptorFromRawManifest("registry.example.com/acme/app:latest", []byte(`{"schemaVersion":2,"manifests":{}}`))
	require.EqualError(t, err, "single-platform image")
}

func TestPlatformImageReferenceFromManifest(t *testing.T) {
	ref := name.MustParseReference("registry.example.com/acme/app:latest")
	rawManifest := []byte(
		`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json",` +
			`"manifests":[{"digest":"sha256:` + strings.Repeat("a", 64) +
			`","platform":{"os":"linux","architecture":"arm64","variant":"v8"}}]}`,
	)

	got, err := platformImageReferenceFromManifest(ref, rawManifest, &ispec.Platform{OS: "linux", Architecture: "arm64"})
	require.NoError(t, err)
	require.Equal(t, "registry.example.com/acme/app@sha256:"+strings.Repeat("a", 64), got)
}

func BenchmarkDescriptorFromRawManifest(b *testing.B) {
	rawManifest := benchmarkRawIndexManifest(b, 32)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		desc, err := descriptorFromRawManifest("registry.example.com/acme/app:latest", rawManifest)
		if err != nil {
			b.Fatal(err)
		}
		buildkitDescriptorSink = desc
	}
}

func BenchmarkPlatformImageReferenceFromManifest(b *testing.B) {
	rawManifest := benchmarkRawIndexManifest(b, 32)
	ref := name.MustParseReference("registry.example.com/acme/app:latest")
	target := &ispec.Platform{OS: "linux", Architecture: "amd64", Variant: "v31"}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		platformRef, err := platformImageReferenceFromManifest(ref, rawManifest, target)
		if err != nil {
			b.Fatal(err)
		}
		buildkitStringSink = platformRef
	}
}

func BenchmarkPlatformKey(b *testing.B) {
	platforms := []ispec.Platform{
		{OS: "linux", Architecture: "amd64"},
		{OS: "linux", Architecture: "arm", Variant: "v7"},
		{OS: "windows", Architecture: "amd64", OSVersion: "10.0.20348.2031"},
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buildkitStringSink = PlatformKey(platforms[i%len(platforms)])
	}
}
