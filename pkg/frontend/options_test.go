package frontend

import (
	"context"
	"errors"
	"testing"

	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/mocks"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

const standardChiselRelease = "ubuntu-24.04"

// Note: ParseOptions tests are covered by e2e tests in test/e2e/frontend/
// since it requires a real BuildKit gateway client. This file focuses on
// testing the validation helper functions that can be unit tested.

func TestIsNamedChiselRelease(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{name: "standard release", value: standardChiselRelease, expected: true},
		{name: "custom directory suffix", value: "ubuntu-24.04-custom", expected: false},
		{name: "short version component", value: "ubuntu-24.4", expected: false},
		{name: "non-digit version component", value: "ubuntu-2a.04", expected: false},
		{name: "different distribution", value: "debian-24.04", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isNamedChiselRelease(tt.value))
		})
	}
}

func TestParseOptionsChiselRelease(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "direct frontend option", key: keyChiselRelease},
		{name: "build argument", key: "build-arg:" + keyChiselRelease},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := new(mocks.MockGWClient)
			client.On("BuildOpts").Return(gwclient.BuildOpts{
				Opts: map[string]string{
					keyImage: "ubuntu:24.04",
					tt.key:   standardChiselRelease,
				},
				LLBCaps: pb.Caps.CapSet(pb.Caps.All()),
			})

			opts, err := ParseOptions(context.Background(), client)
			require.NoError(t, err)
			assert.Equal(t, standardChiselRelease, opts.ChiselRelease)
			client.AssertExpectations(t)
		})
	}
}

func TestParseOptionsChiselReleaseDirectoryWithNamedPrefixUsesContext(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "direct frontend option", key: keyChiselRelease},
		{name: "build argument", key: "build-arg:" + keyChiselRelease},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			solveErr := errors.New("failed to load release context")
			client := new(mocks.MockGWClient)
			client.On("BuildOpts").Return(gwclient.BuildOpts{
				Opts: map[string]string{
					keyImage: "ubuntu:24.04",
					tt.key:   "ubuntu-24.04-custom",
				},
				LLBCaps: pb.Caps.CapSet(pb.Caps.All()),
			})
			client.On("Solve", mock.Anything, mock.Anything).
				Return((*gwclient.Result)(nil), solveErr).Once()

			opts, err := ParseOptions(context.Background(), client)
			require.Error(t, err)
			assert.Nil(t, opts)
			assert.ErrorIs(t, err, solveErr)
			assert.Contains(t, err.Error(), "failed to extract local Chisel release from context")
			assert.NotContains(t, err.Error(), "invalid Chisel release override")
			client.AssertExpectations(t)
		})
	}
}

func TestParseOptionsRejectsChiselReleaseGitURL(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "direct frontend option", key: keyChiselRelease},
		{name: "build argument", key: "build-arg:" + keyChiselRelease},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := new(mocks.MockGWClient)
			client.On("BuildOpts").Return(gwclient.BuildOpts{
				Opts: map[string]string{
					keyImage: "ubuntu:24.04",
					tt.key:   "https://127.0.0.1/chisel-releases.git#abc123",
				},
				LLBCaps: pb.Caps.CapSet(pb.Caps.All()),
			})

			opts, err := ParseOptions(context.Background(), client)
			require.Error(t, err)
			assert.Nil(t, opts)
			assert.Contains(t, err.Error(), "Chisel release Git URLs are not supported by the BuildKit frontend")
			assert.Contains(t, err.Error(), `dedicated "chisel-release" build context`)
			client.AssertExpectations(t)
		})
	}
}

func TestValidateLibraryPatchLevel(t *testing.T) {
	t.Run("Valid patch levels", func(t *testing.T) {
		validLevels := []string{utils.PatchTypePatch, utils.PatchTypeMinor, utils.PatchTypeMajor}
		for _, level := range validLevels {
			t.Run(level, func(t *testing.T) {
				err := validateLibraryPatchLevel(level, utils.PkgTypeLibrary)
				assert.NoError(t, err)
			})
		}
	})

	t.Run("Invalid patch level", func(t *testing.T) {
		err := validateLibraryPatchLevel("invalid", utils.PkgTypeLibrary)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid library patch level")
	})

	t.Run("Non-patch level without library in pkg-types", func(t *testing.T) {
		err := validateLibraryPatchLevel(utils.PatchTypeMinor, utils.PkgTypeOS)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "library-patch-level can only be used when 'library' is included")
	})

	t.Run("Patch level with library in pkg-types", func(t *testing.T) {
		err := validateLibraryPatchLevel(utils.PatchTypePatch, utils.PkgTypeOS)
		assert.NoError(t, err)
	})
}

func TestParsePkgTypes(t *testing.T) {
	t.Run("Valid OS only", func(t *testing.T) {
		types, err := parsePkgTypes("os")
		require.NoError(t, err)
		assert.Equal(t, []string{utils.PkgTypeOS}, types)
	})

	t.Run("Valid library only", func(t *testing.T) {
		types, err := parsePkgTypes("library")
		require.NoError(t, err)
		assert.Equal(t, []string{utils.PkgTypeLibrary}, types)
	})

	t.Run("Valid OS and library", func(t *testing.T) {
		types, err := parsePkgTypes("os,library")
		require.NoError(t, err)
		assert.Equal(t, []string{utils.PkgTypeOS, utils.PkgTypeLibrary}, types)
	})

	t.Run("Valid library and OS (reversed)", func(t *testing.T) {
		types, err := parsePkgTypes("library,os")
		require.NoError(t, err)
		assert.Equal(t, []string{utils.PkgTypeLibrary, utils.PkgTypeOS}, types)
	})

	t.Run("Empty string defaults to OS", func(t *testing.T) {
		types, err := parsePkgTypes("")
		require.NoError(t, err)
		assert.Equal(t, []string{utils.PkgTypeOS}, types)
	})

	t.Run("Invalid package type", func(t *testing.T) {
		_, err := parsePkgTypes("invalid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid package type")
	})

	t.Run("Mix of valid and invalid", func(t *testing.T) {
		_, err := parsePkgTypes("os,invalid")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid package type")
	})

	t.Run("Whitespace handling", func(t *testing.T) {
		types, err := parsePkgTypes(" os , library ")
		require.NoError(t, err)
		assert.Equal(t, []string{utils.PkgTypeOS, utils.PkgTypeLibrary}, types)
	})
}

func TestValidateLibraryPkgTypesRequireReport(t *testing.T) {
	t.Run("Library requires report", func(t *testing.T) {
		pkgTypes := []string{utils.PkgTypeLibrary}
		err := validateLibraryPkgTypesRequireReport(pkgTypes, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "library package types require a scanner report")
	})

	t.Run("Library with report provided", func(t *testing.T) {
		pkgTypes := []string{utils.PkgTypeLibrary}
		err := validateLibraryPkgTypesRequireReport(pkgTypes, true)
		assert.NoError(t, err)
	})

	t.Run("OS only without report", func(t *testing.T) {
		pkgTypes := []string{utils.PkgTypeOS}
		err := validateLibraryPkgTypesRequireReport(pkgTypes, false)
		assert.NoError(t, err)
	})

	t.Run("OS and library require report", func(t *testing.T) {
		pkgTypes := []string{utils.PkgTypeOS, utils.PkgTypeLibrary}
		err := validateLibraryPkgTypesRequireReport(pkgTypes, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "library package types require a scanner report")
	})
}

func TestShouldIncludeLibraryUpdates(t *testing.T) {
	t.Run("Library in package types", func(t *testing.T) {
		pkgTypes := []string{utils.PkgTypeOS, utils.PkgTypeLibrary}
		assert.True(t, shouldIncludeLibraryUpdates(pkgTypes))
	})

	t.Run("Library only", func(t *testing.T) {
		pkgTypes := []string{utils.PkgTypeLibrary}
		assert.True(t, shouldIncludeLibraryUpdates(pkgTypes))
	})

	t.Run("OS only", func(t *testing.T) {
		pkgTypes := []string{utils.PkgTypeOS}
		assert.False(t, shouldIncludeLibraryUpdates(pkgTypes))
	})

	t.Run("Empty package types", func(t *testing.T) {
		pkgTypes := []string{}
		assert.False(t, shouldIncludeLibraryUpdates(pkgTypes))
	})
}
