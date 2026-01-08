package utils

import (
	"testing"
)

func TestCanonicalOSType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		// Alpine variations
		{name: "alpine exact", input: "alpine", expected: OSTypeAlpine},
		{name: "alpine linux", input: "alpine linux", expected: OSTypeAlpine},
		{name: "Alpine Linux uppercase", input: "Alpine Linux", expected: OSTypeAlpine},

		// Debian variations
		{name: "debian exact", input: "debian", expected: OSTypeDebian},
		{name: "Debian GNU/Linux", input: "Debian GNU/Linux", expected: OSTypeDebian},

		// Ubuntu variations
		{name: "ubuntu exact", input: "ubuntu", expected: OSTypeUbuntu},
		{name: "Ubuntu uppercase", input: "Ubuntu", expected: OSTypeUbuntu},

		// Amazon Linux variations
		{name: "amazon exact", input: "amazon", expected: OSTypeAmazon},
		{name: "Amazon Linux", input: "Amazon Linux", expected: OSTypeAmazon},

		// CentOS variations
		{name: "centos exact", input: "centos", expected: OSTypeCentOS},
		{name: "CentOS Linux", input: "CentOS Linux", expected: OSTypeCentOS},

		// CBL-Mariner variations
		{name: "cbl-mariner exact", input: "cbl-mariner", expected: OSTypeCBLMariner},
		{name: "mariner only", input: "mariner", expected: OSTypeCBLMariner},
		{name: "Common Base Linux Mariner", input: "Common Base Linux Mariner", expected: OSTypeCBLMariner},
		{name: "CBL-Mariner/Linux", input: "CBL-Mariner/Linux", expected: OSTypeCBLMariner},

		// Azure Linux variations
		{name: "azurelinux exact", input: "azurelinux", expected: OSTypeAzureLinux},
		{name: "azure linux with space", input: "azure linux", expected: OSTypeAzureLinux},
		{name: "Microsoft Azure Linux", input: "Microsoft Azure Linux", expected: OSTypeAzureLinux},

		// Red Hat variations
		{name: "redhat exact", input: "redhat", expected: OSTypeRedHat},
		{name: "red hat with space", input: "red hat", expected: OSTypeRedHat},
		{name: "Red Hat Enterprise Linux", input: "Red Hat Enterprise Linux", expected: OSTypeRedHat},

		// Rocky Linux variations
		{name: "rocky exact", input: "rocky", expected: OSTypeRocky},
		{name: "Rocky Linux", input: "Rocky Linux", expected: OSTypeRocky},

		// Oracle Linux variations
		{name: "oracle exact", input: "oracle", expected: OSTypeOracle},
		{name: "Oracle Linux Server", input: "Oracle Linux Server", expected: OSTypeOracle},

		// AlmaLinux variations
		{name: "alma exact", input: "alma", expected: OSTypeAlma},
		{name: "AlmaLinux", input: "AlmaLinux", expected: OSTypeAlma},

		// SLES variations
		{name: "sles exact", input: "sles", expected: OSTypeSLES},
		{name: "SLES uppercase", input: "SLES", expected: OSTypeSLES},
		{name: "suse linux enterprise server", input: "suse linux enterprise server", expected: OSTypeSLES},
		{name: "SUSE Linux Enterprise Server uppercase", input: "SUSE Linux Enterprise Server", expected: OSTypeSLES},

		// openSUSE Leap variations
		{name: "opensuse-leap with dash", input: "opensuse-leap", expected: OSTypeOpenSUSELeap},
		{name: "opensuse leap with space", input: "opensuse leap", expected: OSTypeOpenSUSELeap},
		{name: "openSUSE Leap mixed case", input: "openSUSE Leap", expected: OSTypeOpenSUSELeap},
		{name: "opensuse.leap with dot (Trivy old format)", input: "opensuse.leap", expected: OSTypeOpenSUSELeap},

		// openSUSE Tumbleweed variations
		{name: "opensuse-tumbleweed with dash", input: "opensuse-tumbleweed", expected: OSTypeOpenSUSETW},
		{name: "opensuse tumbleweed with space", input: "opensuse tumbleweed", expected: OSTypeOpenSUSETW},
		{name: "openSUSE Tumbleweed mixed case", input: "openSUSE Tumbleweed", expected: OSTypeOpenSUSETW},
		{name: "opensuse.tumbleweed with dot (Trivy old format)", input: "opensuse.tumbleweed", expected: OSTypeOpenSUSETW},

		// Unsupported/unknown OS returns empty string
		{name: "unknown os", input: "windows", expected: ""},
		{name: "empty string", input: "", expected: ""},
		{name: "random string", input: "someunknownos", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CanonicalOSType(tt.input)
			if result != tt.expected {
				t.Errorf("CanonicalOSType(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}
