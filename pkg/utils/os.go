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
	os := strings.ToLower(osType)

	switch {
	case strings.Contains(os, OSTypeAlpine):
		return OSTypeAlpine
	case strings.Contains(os, OSTypeDebian):
		return OSTypeDebian
	case strings.Contains(os, OSTypeUbuntu):
		return OSTypeUbuntu
	case strings.Contains(os, OSTypeAmazon):
		return OSTypeAmazon
	case strings.Contains(os, OSTypeCentOS):
		return OSTypeCentOS
	case strings.Contains(os, OSTypeCBLMariner), strings.Contains(os, "mariner"):
		return OSTypeCBLMariner
	case strings.Contains(os, OSTypeAzureLinux), strings.Contains(os, "azure linux"):
		return OSTypeAzureLinux
	case strings.Contains(os, OSTypeRedHat), strings.Contains(os, "red hat"):
		return OSTypeRedHat
	case strings.Contains(os, OSTypeRocky):
		return OSTypeRocky
	case strings.Contains(os, OSTypeOracle):
		return OSTypeOracle
	case strings.Contains(os, OSTypeAlma):
		return OSTypeAlma
	case strings.Contains(os, OSTypeSLES), strings.Contains(os, "suse linux enterprise server"):
		return OSTypeSLES
	case strings.Contains(os, OSTypeOpenSUSELeap), strings.Contains(os, "opensuse leap"), strings.Contains(os, "opensuse.leap"):
		return OSTypeOpenSUSELeap
	case strings.Contains(os, OSTypeOpenSUSETW), strings.Contains(os, "opensuse tumbleweed"), strings.Contains(os, "opensuse.tumbleweed"):
		return OSTypeOpenSUSETW
	default:
		return ""
	}
}
