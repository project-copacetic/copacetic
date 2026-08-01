package chisel

import (
	"fmt"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	ociOSLinux        = "linux"
	ociArchAMD64      = "amd64"
	ociArchARM64      = "arm64"
	ociArch386        = "386"
	ociArchARM        = "arm"
	ociArchPPC64LE    = "ppc64le"
	ociArchS390X      = "s390x"
	ociArchRISCV64    = "riscv64"
	chiselArchI386    = "i386"
	chiselArchARMHF   = "armhf"
	chiselArchPPC64EL = "ppc64el"
)

// OCIPlatformToChiselArch maps a Linux OCI platform to the Debian
// architecture name accepted by Chisel.
//
//nolint:gocritic // Taking this small descriptor by value matches common OCI platform APIs.
func OCIPlatformToChiselArch(platform ocispec.Platform) (string, error) {
	if platform.OS != "" && platform.OS != ociOSLinux {
		return "", fmt.Errorf("unsupported Chisel platform %s", formatPlatform(&platform))
	}

	switch platform.Architecture {
	case ociArchAMD64:
		return ociArchAMD64, nil
	case ociArchARM64:
		return ociArchARM64, nil
	case ociArch386:
		return chiselArchI386, nil
	case ociArchPPC64LE:
		return chiselArchPPC64EL, nil
	case ociArchS390X:
		return ociArchS390X, nil
	case ociArchRISCV64:
		return ociArchRISCV64, nil
	case ociArchARM:
		switch strings.TrimPrefix(platform.Variant, "v") {
		case "7":
			return chiselArchARMHF, nil
		case "6":
			return "", fmt.Errorf("unsupported Chisel platform linux/arm/v6")
		default:
			return "", fmt.Errorf("unsupported Chisel ARM variant %q; only linux/arm/v7 is supported", platform.Variant)
		}
	default:
		return "", fmt.Errorf("unsupported Chisel platform %s", formatPlatform(&platform))
	}
}

func formatPlatform(platform *ocispec.Platform) string {
	operatingSystem := platform.OS
	if operatingSystem == "" {
		operatingSystem = ociOSLinux
	}
	formatted := operatingSystem + "/" + platform.Architecture
	if platform.Variant != "" {
		formatted += "/" + platform.Variant
	}
	return formatted
}
