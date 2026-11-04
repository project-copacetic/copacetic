package chisel

import (
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOCIPlatformToChiselArch(t *testing.T) {
	tests := []struct {
		name        string
		platform    ocispec.Platform
		expected    string
		errContains string
	}{
		{name: ociArchAMD64, platform: ocispec.Platform{OS: ociOSLinux, Architecture: ociArchAMD64}, expected: ociArchAMD64},
		{name: ociArchARM64, platform: ocispec.Platform{OS: ociOSLinux, Architecture: ociArchARM64}, expected: ociArchARM64},
		{name: ociArch386, platform: ocispec.Platform{OS: ociOSLinux, Architecture: ociArch386}, expected: chiselArchI386},
		{name: "arm v7", platform: ocispec.Platform{OS: ociOSLinux, Architecture: ociArchARM, Variant: "v7"}, expected: chiselArchARMHF},
		{name: "arm bare 7", platform: ocispec.Platform{OS: ociOSLinux, Architecture: ociArchARM, Variant: "7"}, expected: chiselArchARMHF},
		{name: ociArchPPC64LE, platform: ocispec.Platform{OS: ociOSLinux, Architecture: ociArchPPC64LE}, expected: chiselArchPPC64EL},
		{name: ociArchS390X, platform: ocispec.Platform{OS: ociOSLinux, Architecture: ociArchS390X}, expected: ociArchS390X},
		{name: ociArchRISCV64, platform: ocispec.Platform{OS: ociOSLinux, Architecture: ociArchRISCV64}, expected: ociArchRISCV64},
		{name: "empty OS defaults to Linux", platform: ocispec.Platform{Architecture: ociArchAMD64}, expected: ociArchAMD64},
		{
			name:        "arm v6 is explicitly unsupported",
			platform:    ocispec.Platform{OS: ociOSLinux, Architecture: ociArchARM, Variant: "v6"},
			errContains: "unsupported Chisel platform linux/arm/v6",
		},
		{
			name:        "arm without variant is unsupported",
			platform:    ocispec.Platform{OS: ociOSLinux, Architecture: ociArchARM},
			errContains: "only linux/arm/v7 is supported",
		},
		{
			name:        "non-Linux OS is unsupported",
			platform:    ocispec.Platform{OS: "windows", Architecture: ociArchAMD64},
			errContains: "unsupported Chisel platform windows/amd64",
		},
		{
			name:        "unknown architecture is unsupported",
			platform:    ocispec.Platform{OS: ociOSLinux, Architecture: "mips64"},
			errContains: "unsupported Chisel platform linux/mips64",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := OCIPlatformToChiselArch(test.platform)
			if test.errContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expected, actual)
		})
	}
}
