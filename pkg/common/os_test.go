package common

import (
	"context"
	"errors"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestGetOSInfo(t *testing.T) {
	tests := []struct {
		name        string
		osRelease   string
		wantType    string
		wantVersion string
		wantErr     bool
		errContains string
	}{
		// Basic test cases
		{
			name: "Ubuntu",
			osRelease: `NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.1 LTS (Jammy Jellyfish)"`,
			wantType:    utils.OSTypeUbuntu,
			wantVersion: "22.04",
		},
		{
			name: "Alpine",
			osRelease: `NAME="Alpine Linux"
VERSION_ID="3.18.0"`,
			wantType:    utils.OSTypeAlpine,
			wantVersion: "3.18.0",
		},
		{
			name: "Debian",
			osRelease: `NAME="Debian GNU/Linux"
VERSION_ID="11"`,
			wantType:    utils.OSTypeDebian,
			wantVersion: "11",
		},
		{
			name: "Amazon Linux",
			osRelease: `NAME="Amazon Linux"
VERSION_ID="2"`,
			wantType:    utils.OSTypeAmazon,
			wantVersion: "2",
		},
		{
			name: "CentOS",
			osRelease: `NAME="CentOS Linux"
VERSION_ID="8"`,
			wantType:    utils.OSTypeCentOS,
			wantVersion: "8",
		},
		{
			name: "CBL-Mariner",
			osRelease: `NAME="CBL-Mariner/Linux"
VERSION_ID="2.0"`,
			wantType:    utils.OSTypeCBLMariner,
			wantVersion: "2.0",
		},
		{
			name: "Azure Linux",
			osRelease: `NAME="Microsoft Azure Linux"
VERSION_ID="3.0"`,
			wantType:    utils.OSTypeAzureLinux,
			wantVersion: "3.0",
		},
		{
			name: "Red Hat",
			osRelease: `NAME="Red Hat Enterprise Linux"
VERSION_ID="8.5"`,
			wantType:    utils.OSTypeRedHat,
			wantVersion: "8.5",
		},
		{
			name: "Rocky Linux",
			osRelease: `NAME="Rocky Linux"
VERSION_ID="8.5"`,
			wantType:    utils.OSTypeRocky,
			wantVersion: "8.5",
		},
		{
			name: "Oracle Linux",
			osRelease: `NAME="Oracle Linux Server"
VERSION_ID="8.5"`,
			wantType:    utils.OSTypeOracle,
			wantVersion: "8.5",
		},
		{
			name: "AlmaLinux",
			osRelease: `NAME="AlmaLinux"
VERSION_ID="9.1"`,
			wantType:    utils.OSTypeAlma,
			wantVersion: "9.1",
		},
		{
			name: "Debian Full",
			osRelease: `PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"`,
			wantType:    utils.OSTypeDebian,
			wantVersion: "11",
		},
		{
			name: "Alpine Full",
			osRelease: `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.7.3
PRETTY_NAME="Alpine Linux v3.7"
HOME_URL="http://alpinelinux.org"
BUG_REPORT_URL="http://bugs.alpinelinux.org"`,
			wantType:    utils.OSTypeAlpine,
			wantVersion: "3.7.3",
		},
		{
			name: "Ubuntu Full",
			osRelease: `PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy`,
			wantType:    utils.OSTypeUbuntu,
			wantVersion: "22.04",
		},
		{
			name: "Amazon Linux Full",
			osRelease: `NAME="Amazon Linux"
VERSION="2023"
ID="amzn"
ID_LIKE="fedora"
VERSION_ID="2023"
PLATFORM_ID="platform:al2023"
PRETTY_NAME="Amazon Linux 2023.3.20240312"
ANSI_COLOR="0;33"
CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2023"
HOME_URL="https://aws.amazon.com/linux/amazon-linux-2023/"
DOCUMENTATION_URL="https://docs.aws.amazon.com/linux/"
SUPPORT_URL="https://aws.amazon.com/premiumsupport/"
BUG_REPORT_URL="https://github.com/amazonlinux/amazon-linux-2023"
VENDOR_NAME="AWS"
VENDOR_URL="https://aws.amazon.com/"
SUPPORT_END="2028-03-15"`,
			wantType:    utils.OSTypeAmazon,
			wantVersion: "2023",
		},
		{
			name: "CentOS Full",
			osRelease: `NAME="CentOS Linux"
VERSION="8"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="8"
PLATFORM_ID="platform:el8"
PRETTY_NAME="CentOS Linux 8"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:centos:centos:8"
HOME_URL="https://centos.org/"
BUG_REPORT_URL="https://bugs.centos.org/"
CENTOS_MANTISBT_PROJECT="CentOS-8"
CENTOS_MANTISBT_PROJECT_VERSION="8"`,
			wantType:    utils.OSTypeCentOS,
			wantVersion: "8",
		},
		{
			name: "CBL-Mariner Full",
			osRelease: `NAME="Common Base Linux Mariner"
VERSION="2.0.20240117"
ID=mariner
VERSION_ID="2.0"
PRETTY_NAME="CBL-Mariner/Linux"
ANSI_COLOR="1;34"
HOME_URL="https://aka.ms/cbl-mariner"
BUG_REPORT_URL="https://aka.ms/cbl-mariner"
SUPPORT_URL="https://aka.ms/cbl-mariner"`,
			wantType:    utils.OSTypeCBLMariner,
			wantVersion: "2.0",
		},
		{
			name: "Azure Linux Full",
			osRelease: `NAME="Microsoft Azure Linux"
VERSION="3.0.20240727"
ID=azurelinux
VERSION_ID="3.0"
PRETTY_NAME="Microsoft Azure Linux 3.0"
ANSI_COLOR="1;34"
HOME_URL="https://aka.ms/azurelinux"
BUG_REPORT_URL="https://aka.ms/azurelinux"
SUPPORT_URL="https://aka.ms/azurelinux"`,
			wantType:    utils.OSTypeAzureLinux,
			wantVersion: "3.0",
		},
		{
			name: "Red Hat Full",
			osRelease: `NAME="Red Hat Enterprise Linux"
VERSION="8.9 (Ootpa)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="8.9"
PLATFORM_ID="platform:el8"
PRETTY_NAME="Red Hat Enterprise Linux 8.9 (Ootpa)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:8::baseos"
HOME_URL="https://www.redhat.com/"
DOCUMENTATION_URL="https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8"
BUG_REPORT_URL="https://bugzilla.redhat.com/"

REDHAT_BUGZILLA_PRODUCT="Red Hat Enterprise Linux 8"
REDHAT_BUGZILLA_PRODUCT_VERSION=8.9
REDHAT_SUPPORT_PRODUCT="Red Hat Enterprise Linux"
REDHAT_SUPPORT_PRODUCT_VERSION="8.9"`,
			wantType:    utils.OSTypeRedHat,
			wantVersion: "8.9",
		},
		{
			name: "Rocky Linux Full",
			osRelease: `NAME="Rocky Linux"
VERSION="9.3 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.3"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Rocky Linux 9.3 (Blue Onyx)"
ANSI_COLOR="0;32"
LOGO="fedora-logo-icon"
CPE_NAME="cpe:/o:rocky:rocky:9::baseos"
HOME_URL="https://rockylinux.org/"
BUG_REPORT_URL="https://bugs.rockylinux.org/"
SUPPORT_END="2032-05-31"
ROCKY_SUPPORT_PRODUCT="Rocky-Linux-9"
ROCKY_SUPPORT_PRODUCT_VERSION="9.3"
REDHAT_SUPPORT_PRODUCT="Rocky Linux"
REDHAT_SUPPORT_PRODUCT_VERSION="9.3"`,
			wantType:    utils.OSTypeRocky,
			wantVersion: "9.3",
		},
		{
			name: "Oracle Linux 7.9",
			osRelease: `NAME="Oracle Linux Server"
VERSION="7.9"
ID="ol"
ID_LIKE="fedora"
VARIANT="Server"
VARIANT_ID="server"
VERSION_ID="7.9"
PRETTY_NAME="Oracle Linux Server 7.9"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:oracle:linux:7:9:server"
HOME_URL="https://linux.oracle.com/"
BUG_REPORT_URL="https://github.com/oracle/oracle-linux"

ORACLE_BUGZILLA_PRODUCT="Oracle Linux 7"
ORACLE_BUGZILLA_PRODUCT_VERSION=7.9
ORACLE_SUPPORT_PRODUCT="Oracle Linux"
ORACLE_SUPPORT_PRODUCT_VERSION=7.9`,
			wantType:    utils.OSTypeOracle,
			wantVersion: "7.9",
		},
		{
			name: "Oracle Linux 8.9",
			osRelease: `NAME="Oracle Linux Server"
VERSION="8.9"
ID="ol"
ID_LIKE="fedora"
VARIANT="Server"
VARIANT_ID="server"
VERSION_ID="8.9"
PLATFORM_ID="platform:el8"
PRETTY_NAME="Oracle Linux Server 8.9"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:oracle:linux:8:9:server"
HOME_URL="https://linux.oracle.com/"
BUG_REPORT_URL="https://github.com/oracle/oracle-linux"

ORACLE_BUGZILLA_PRODUCT="Oracle Linux 8"
ORACLE_BUGZILLA_PRODUCT_VERSION=8.9
ORACLE_SUPPORT_PRODUCT="Oracle Linux"
ORACLE_SUPPORT_PRODUCT_VERSION=8.9`,
			wantType:    utils.OSTypeOracle,
			wantVersion: "8.9",
		},
		{
			name: "AlmaLinux Full",
			osRelease: `NAME="AlmaLinux"
VERSION="9.4 (Seafoam Ocelot)"
ID="almalinux"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="AlmaLinux 9.4 (Seafoam Ocelot)"
ANSI_COLOR="0;34"
CPE_NAME="cpe:/o:almalinux:almalinux:9::baseos"
HOME_URL="https://almalinux.org/"
DOCUMENTATION_URL="https://wiki.almalinux.org/"
BUG_REPORT_URL="https://bugs.almalinux.org/"

SUPPORT_END="2032-06-01"
ALMALINUX_MANTISBT_PROJECT="AlmaLinux-9"
ALMALINUX_MANTISBT_PROJECT_VERSION="9.4"
REDHAT_SUPPORT_PRODUCT="AlmaLinux"
REDHAT_SUPPORT_PRODUCT_VERSION="9.4"`,
			wantType:    utils.OSTypeAlma,
			wantVersion: "9.4",
		},
		// Minimal test cases
		{
			name: "Debian Minimal",
			osRelease: `PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"`,
			wantType:    utils.OSTypeDebian,
			wantVersion: "11",
		},
		{
			name: "Alpine Minimal",
			osRelease: `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.7.3`,
			wantType:    utils.OSTypeAlpine,
			wantVersion: "3.7.3",
		},
		// Edge cases for OS detection matching old test behavior
		{
			name: "CBL-Mariner alternative name",
			osRelease: `NAME="Common Base Linux Mariner"
VERSION_ID="2.0"`,
			wantType:    utils.OSTypeCBLMariner,
			wantVersion: "2.0",
		},
		// Error cases
		{
			name: "Unsupported OS",
			osRelease: `NAME="Unknown Linux"
VERSION_ID="1.0"`,
			wantErr: true,
		},
		{
			name: "Another unsupported OS",
			osRelease: `NAME="SomeRandomOS"
ID=someos
VERSION_ID=1.0`,
			wantErr: true,
		},
		{
			name:      "Invalid Format",
			osRelease: `invalid data`,
			wantErr:   true,
		},
		{
			name:        "Cannot Parse Version_ID",
			osRelease:   `Cannot Parse Version_ID`,
			wantErr:     true,
			errContains: "unable to parse os-release data",
		},
		{
			name:      "Empty os-release",
			osRelease: ``,
			wantErr:   true,
		},
		{
			name: "Missing VERSION_ID (should work, return empty version)",
			osRelease: `PRETTY_NAME="Debian GNU/Linux"
NAME="Debian GNU/Linux"
ID=debian`,
			wantType:    utils.OSTypeDebian,
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			osInfo, err := GetOSInfo(ctx, []byte(tt.osRelease))

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, osInfo)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				// Check for specific error type when appropriate
				if tt.name == "Unsupported OS" || tt.name == "Another unsupported OS" {
					assert.True(t, errors.Is(err, errors.ErrUnsupported))
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, osInfo)
				assert.Equal(t, tt.wantType, osInfo.Type)
				assert.Equal(t, tt.wantVersion, osInfo.Version)
			}
		})
	}
}
