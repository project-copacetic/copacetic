package utils

import (
	"strings"
)

// Canonical supported OS (distribution) identifiers used across Copacetic.
// Centralizing them avoids string literal drift and enables IDE refactors.
// These values correspond to normalized distro 'Type' values in manifests and
// inputs to GetPackageManager.
const (
	OSTypeAlpine       = "alpine"
	OSTypeDebian       = "debian"
	OSTypeUbuntu       = "ubuntu"
	OSTypeCBLMariner   = "cbl-mariner"
	OSTypeAzureLinux   = "azurelinux"
	OSTypeCentOS       = "centos"
	OSTypeOracle       = "oracle"
	OSTypeRedHat       = "redhat"
	OSTypeRocky        = "rocky"
	OSTypeAmazon       = "amazon"
	OSTypeAlma         = "alma"
	OSTypeAlmaLinux    = "almalinux"
	OSTypeSLES         = "sles"
	OSTypeOpenSUSELeap = "opensuse-leap"
	OSTypeOpenSUSETW   = "opensuse-tumbleweed"
)

// RPMDistros is a helper slice listing rpm-family OS identifiers.
var RPMDistros = []string{
	OSTypeCBLMariner,
	OSTypeAzureLinux,
	OSTypeCentOS,
	OSTypeOracle,
	OSTypeRedHat,
	OSTypeRocky,
	OSTypeAmazon,
	OSTypeAlma,
	OSTypeAlmaLinux,
	OSTypeSLES,
	OSTypeOpenSUSELeap,
	OSTypeOpenSUSETW,
}

func CanonicalOSType(osType string) string {
	switch {
	case strings.Contains(osType, OSTypeAlpine):
		return OSTypeAlpine
	case strings.Contains(osType, OSTypeDebian):
		return OSTypeDebian
	case strings.Contains(osType, OSTypeUbuntu):
		return OSTypeUbuntu
	case strings.Contains(osType, OSTypeAmazon):
		return OSTypeAmazon
	case strings.Contains(osType, OSTypeCentOS):
		return OSTypeCentOS
	case strings.Contains(osType, OSTypeCBLMariner), strings.Contains(osType, "mariner"):
		return OSTypeCBLMariner
	case strings.Contains(osType, OSTypeAzureLinux), strings.Contains(osType, "azure linux"):
		return OSTypeAzureLinux
	case strings.Contains(osType, OSTypeRedHat), strings.Contains(osType, "red hat"):
		return OSTypeRedHat
	case strings.Contains(osType, OSTypeRocky):
		return OSTypeRocky
	case strings.Contains(osType, OSTypeOracle):
		return OSTypeOracle
	case strings.Contains(osType, OSTypeAlma):
		return OSTypeAlma
	case strings.Contains(osType, OSTypeSLES), strings.Contains(osType, "suse linux enterprise server"):
		return OSTypeSLES
	case strings.Contains(osType, OSTypeOpenSUSELeap), strings.Contains(osType, "opensuse leap"), strings.Contains(osType, "opensuse.leap"):
		return OSTypeOpenSUSELeap
	case strings.Contains(osType, OSTypeOpenSUSETW), strings.Contains(osType, "opensuse tumbleweed"), strings.Contains(osType, "opensuse.tumbleweed"):
		return OSTypeOpenSUSETW
	default:
		return ""
	}
}
