package types

import (
	"encoding/json"
	"testing"

	"github.com/distribution/reference"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdatePackage(t *testing.T) {
	t.Run("JSON marshaling", func(t *testing.T) {
		pkg := UpdatePackage{
			Name:             "test-package",
			InstalledVersion: "1.0.0",
			FixedVersion:     "1.0.1",
			VulnerabilityID:  "CVE-2023-1234",
		}

		data, err := json.Marshal(pkg)
		require.NoError(t, err)

		expected := `{"name":"test-package","installedVersion":"1.0.0","fixedVersion":"1.0.1","vulnerabilityID":"CVE-2023-1234"}`
		assert.JSONEq(t, expected, string(data))
	})

	t.Run("JSON unmarshaling", func(t *testing.T) {
		jsonData := `{"name":"test-package","installedVersion":"1.0.0","fixedVersion":"1.0.1","vulnerabilityID":"CVE-2023-1234"}`

		var pkg UpdatePackage
		err := json.Unmarshal([]byte(jsonData), &pkg)
		require.NoError(t, err)

		assert.Equal(t, "test-package", pkg.Name)
		assert.Equal(t, "1.0.0", pkg.InstalledVersion)
		assert.Equal(t, "1.0.1", pkg.FixedVersion)
		assert.Equal(t, "CVE-2023-1234", pkg.VulnerabilityID)
	})

	t.Run("Empty fields", func(t *testing.T) {
		pkg := UpdatePackage{}
		data, err := json.Marshal(pkg)
		require.NoError(t, err)

		expected := `{"name":"","installedVersion":"","fixedVersion":"","vulnerabilityID":""}`
		assert.JSONEq(t, expected, string(data))
	})
}

func TestUpdatePackages(t *testing.T) {
	t.Run("Array marshaling", func(t *testing.T) {
		packages := UpdatePackages{
			{
				Name:             "package1",
				InstalledVersion: "1.0.0",
				FixedVersion:     "1.0.1",
				VulnerabilityID:  "CVE-2023-1234",
			},
			{
				Name:             "package2",
				InstalledVersion: "2.0.0",
				FixedVersion:     "2.0.1",
				VulnerabilityID:  "CVE-2023-5678",
			},
		}

		data, err := json.Marshal(packages)
		require.NoError(t, err)

		var unmarshaled UpdatePackages
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Len(t, unmarshaled, 2)
		assert.Equal(t, "package1", unmarshaled[0].Name)
		assert.Equal(t, "package2", unmarshaled[1].Name)
	})

	t.Run("Empty array", func(t *testing.T) {
		packages := UpdatePackages{}
		data, err := json.Marshal(packages)
		require.NoError(t, err)

		assert.Equal(t, "[]", string(data))
	})

	t.Run("Nil array", func(t *testing.T) {
		var packages UpdatePackages
		data, err := json.Marshal(packages)
		require.NoError(t, err)

		assert.Equal(t, "null", string(data))
	})
}

func TestUpdateManifest(t *testing.T) {
	t.Run("Complete manifest", func(t *testing.T) {
		manifest := UpdateManifest{
			OSType:    "linux",
			OSVersion: "ubuntu22.04",
			Arch:      "amd64",
			Updates: UpdatePackages{
				{
					Name:             "openssl",
					InstalledVersion: "1.1.1",
					FixedVersion:     "1.1.2",
					VulnerabilityID:  "CVE-2023-1234",
				},
			},
		}

		data, err := json.Marshal(manifest)
		require.NoError(t, err)

		var unmarshaled UpdateManifest
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, "linux", unmarshaled.OSType)
		assert.Equal(t, "ubuntu22.04", unmarshaled.OSVersion)
		assert.Equal(t, "amd64", unmarshaled.Arch)
		assert.Len(t, unmarshaled.Updates, 1)
		assert.Equal(t, "openssl", unmarshaled.Updates[0].Name)
	})

	t.Run("Empty manifest", func(t *testing.T) {
		manifest := UpdateManifest{}
		data, err := json.Marshal(manifest)
		require.NoError(t, err)

		expected := `{"osType":"","osVersion":"","arch":"","updates":null}`
		assert.JSONEq(t, expected, string(data))
	})
}

func TestPatchPlatform(t *testing.T) {
	t.Run("String method without variant", func(t *testing.T) {
		platform := PatchPlatform{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			ReportFile:     "/path/to/report.json",
			ShouldPreserve: true,
		}

		result := platform.String()
		assert.Equal(t, "linux/amd64", result)
	})

	t.Run("String method with variant", func(t *testing.T) {
		platform := PatchPlatform{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "arm",
				Variant:      "v7",
			},
			ReportFile:     "/path/to/report.json",
			ShouldPreserve: false,
		}

		result := platform.String()
		assert.Equal(t, "linux/arm/v7", result)
	})

	t.Run("String method with empty variant", func(t *testing.T) {
		platform := PatchPlatform{
			Platform: ispec.Platform{
				OS:           "windows",
				Architecture: "amd64",
				Variant:      "",
			},
		}

		result := platform.String()
		assert.Equal(t, "windows/amd64", result)
	})

	t.Run("JSON marshaling", func(t *testing.T) {
		platform := PatchPlatform{
			Platform: ispec.Platform{
				OS:           "linux",
				Architecture: "amd64",
			},
			ReportFile:     "/path/to/report.json",
			ShouldPreserve: true,
		}

		data, err := json.Marshal(platform)
		require.NoError(t, err)

		var unmarshaled PatchPlatform
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, "linux", unmarshaled.OS)
		assert.Equal(t, "amd64", unmarshaled.Architecture)
		assert.Equal(t, "/path/to/report.json", unmarshaled.ReportFile)
		assert.True(t, unmarshaled.ShouldPreserve)
	})
}

func TestPatchResult(t *testing.T) {
	t.Run("Complete PatchResult", func(t *testing.T) {
		originalRef, err := reference.ParseNormalizedNamed("registry.io/original:tag")
		require.NoError(t, err)

		patchedRef, err := reference.ParseNormalizedNamed("registry.io/patched:tag")
		require.NoError(t, err)

		desc := &ispec.Descriptor{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    "sha256:1234567890abcdef",
			Size:      1024,
		}

		result := PatchResult{
			OriginalRef: originalRef,
			PatchedDesc: desc,
			PatchedRef:  patchedRef,
		}

		assert.Equal(t, "registry.io/original:tag", result.OriginalRef.String())
		assert.Equal(t, "registry.io/patched:tag", result.PatchedRef.String())
		assert.Equal(t, "application/vnd.oci.image.manifest.v1+json", result.PatchedDesc.MediaType)
		assert.Equal(t, int64(1024), result.PatchedDesc.Size)
	})

	t.Run("Nil descriptor", func(t *testing.T) {
		originalRef, err := reference.ParseNormalizedNamed("registry.io/original:tag")
		require.NoError(t, err)

		patchedRef, err := reference.ParseNormalizedNamed("registry.io/patched:tag")
		require.NoError(t, err)

		result := PatchResult{
			OriginalRef: originalRef,
			PatchedDesc: nil,
			PatchedRef:  patchedRef,
		}

		assert.Nil(t, result.PatchedDesc)
		assert.NotNil(t, result.OriginalRef)
		assert.NotNil(t, result.PatchedRef)
	})
}

func TestMultiPlatformSummary(t *testing.T) {
	t.Run("JSON marshaling", func(t *testing.T) {
		summary := MultiPlatformSummary{
			Platform: "linux/amd64",
			Status:   "success",
			Ref:      "registry.io/image:tag",
			Message:  "Patch completed successfully",
		}

		data, err := json.Marshal(summary)
		require.NoError(t, err)

		var unmarshaled MultiPlatformSummary
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)

		assert.Equal(t, "linux/amd64", unmarshaled.Platform)
		assert.Equal(t, "success", unmarshaled.Status)
		assert.Equal(t, "registry.io/image:tag", unmarshaled.Ref)
		assert.Equal(t, "Patch completed successfully", unmarshaled.Message)
	})

	t.Run("Empty fields", func(t *testing.T) {
		summary := MultiPlatformSummary{}
		data, err := json.Marshal(summary)
		require.NoError(t, err)

		expected := `{"Platform":"","Status":"","Ref":"","Message":""}`
		assert.JSONEq(t, expected, string(data))
	})

	t.Run("Error status", func(t *testing.T) {
		summary := MultiPlatformSummary{
			Platform: "linux/arm64",
			Status:   "error",
			Ref:      "registry.io/image:tag",
			Message:  "Build failed: missing dependency",
		}

		assert.Equal(t, "error", summary.Status)
		assert.Contains(t, summary.Message, "Build failed")
	})
}
