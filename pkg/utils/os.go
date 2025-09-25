package utils

// Canonical supported OS (distribution) identifiers used across Copacetic.
// Centralizing them avoids string literal drift and enables IDE refactors.
// These values correspond to normalized distro 'Type' values in manifests and
// inputs to GetPackageManager.
const (
	OSTypeAlpine     = "alpine"
	OSTypeDebian     = "debian"
	OSTypeUbuntu     = "ubuntu"
	OSTypeCBLMariner = "cbl-mariner"
	OSTypeAzureLinux = "azurelinux"
	OSTypeCentOS     = "centos"
	OSTypeOracle     = "oracle"
	OSTypeRedHat     = "redhat"
	OSTypeRocky      = "rocky"
	OSTypeAmazon     = "amazon"
	OSTypeAlma       = "alma"
	OSTypeAlmaLinux  = "almalinux"
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
}
