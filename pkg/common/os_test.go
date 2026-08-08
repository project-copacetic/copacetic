package common

import (
	"context"
	"errors"
	"testing"
	"time"

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
			name: "Debian ID fallback",
			osRelease: `ID=debian
VERSION_ID=13`,
			wantType:    utils.OSTypeDebian,
			wantVersion: "13",
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
			wantType:    utils.OSTypeAlmaLinux,
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
			wantType:    utils.OSTypeAlmaLinux,
			wantVersion: "9.4",
		},
		{
			name: "SLES and BCI",
			osRelease: `NAME="SLES"
VERSION="15-SP7"
VERSION_ID="15.7"
PRETTY_NAME="SUSE Linux Enterprise Server 15 SP7"
ID="sles"
ID_LIKE="suse"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:suse:sles:15:sp7"
DOCUMENTATION_URL="https://documentation.suse.com/"`,
			wantType:    utils.OSTypeSLES,
			wantVersion: "15.7",
		},
		{
			name: "opensuse Leap",
			osRelease: `NAME="openSUSE Leap"
VERSION="15.6"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
VERSION_ID="15.6"
PRETTY_NAME="openSUSE Leap 15.6"
ANSI_COLOR="0;32"
CPE_NAME="cpe:/o:opensuse:leap:15.6"
BUG_REPORT_URL="https://bugs.opensuse.org"
HOME_URL="https://www.opensuse.org/"
DOCUMENTATION_URL="https://en.opensuse.org/Portal:Leap"
LOGO="distributor-logo-Leap"`,
			wantType:    utils.OSTypeOpenSUSELeap,
			wantVersion: "15.6",
		},
		{
			name: "openSUSE Tumbleweed",
			osRelease: `NAME="openSUSE Tumbleweed"
# VERSION="20250910"
ID="opensuse-tumbleweed"
ID_LIKE="opensuse suse"
VERSION_ID="20250910"
PRETTY_NAME="openSUSE Tumbleweed"
ANSI_COLOR="0;32"
# CPE 2.3 format, boo#1217921
CPE_NAME="cpe:2.3:o:opensuse:tumbleweed:20250910:*:*:*:*:*:*:*"
#CPE 2.2 format
#CPE_NAME="cpe:/o:opensuse:tumbleweed:20250910"
BUG_REPORT_URL="https://bugzilla.opensuse.org"
SUPPORT_URL="https://bugs.opensuse.org"
HOME_URL="https://www.opensuse.org"
DOCUMENTATION_URL="https://en.opensuse.org/Portal:Tumbleweed"
LOGO="distributor-logo-Tumbleweed"`,
			wantType:    utils.OSTypeOpenSUSETW,
			wantVersion: "20250910",
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
			name: "Malformed unused extension does not block detection",
			osRelease: `NAME=Ubuntu
VERSION_ID=24.04
VENDOR=$ACME`,
			wantType:    utils.OSTypeUbuntu,
			wantVersion: "24.04",
		},
		{
			name:      "Malformed required name remains invalid",
			osRelease: `NAME=$Ubuntu`,
			wantErr:   true,
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

func TestGetOSInfoHonorsContext(t *testing.T) {
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	deadlineCtx, deadlineCancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	t.Cleanup(deadlineCancel)

	tests := []struct {
		name    string
		ctx     context.Context
		wantErr error
	}{
		{name: "canceled", ctx: canceledCtx, wantErr: context.Canceled},
		{name: "deadline exceeded", ctx: deadlineCtx, wantErr: context.DeadlineExceeded},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osInfo, err := GetOSInfo(tt.ctx, []byte("NAME=Debian\nVERSION_ID=13"))
			assert.Nil(t, osInfo)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestValidOSReleaseKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{name: "canonical name", key: "NAME", want: true},
		{name: "canonical version ID", key: "VERSION_ID", want: true},
		{name: "canonical ID like", key: "ID_LIKE", want: true},
		{name: "lowercase extension", key: "x_vendor_feature", want: true},
		{name: "leading underscore", key: "_VENDOR_EXTENSION", want: true},
		{name: "non-ASCII uppercase", key: "NÄME", want: false},
		{name: "non-ASCII digit", key: "NAME١", want: false},
		{name: "leading digit", key: "1NAME", want: false},
		{name: "leading punctuation", key: ".NAME", want: false},
		{name: "embedded punctuation", key: "NAME-DASH", want: false},
		{name: "empty", key: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, validOSReleaseKey(tt.key))
		})
	}
}

func TestParseOSReleaseAcceptsLowercaseExtensionKey(t *testing.T) {
	values, err := parseOSRelease(context.Background(), []byte("NAME=Ubuntu\nVERSION_ID=24.04\nx_vendor_feature=enabled\n"))
	assert.NoError(t, err)
	assert.Equal(t, "enabled", values["x_vendor_feature"])
}

func TestParseOSReleaseShellEscapes(t *testing.T) {
	values, err := parseOSRelease(context.Background(), []byte("NAME=Amazon\\ Linux\nVERSION_ID=2023\\ \n"))
	assert.NoError(t, err)
	assert.Equal(t, "Amazon Linux", values["NAME"])
	assert.Equal(t, "2023 ", values["VERSION_ID"])
}

func TestParseOSReleaseRejectsOversizedInput(t *testing.T) {
	values, err := parseOSRelease(context.Background(), make([]byte, maxOSReleaseSize+1))
	assert.Nil(t, values)
	assert.ErrorContains(t, err, "exceeds")
}

func TestParseOSReleaseValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{
			name:  "empty",
			value: "",
			want:  "",
		},
		{
			name:  "plain value",
			value: "3.7.3",
			want:  "3.7.3",
		},
		{
			name:  "unquoted escaped whitespace",
			value: `Amazon\ Linux`,
			want:  "Amazon Linux",
		},
		{
			name:  "unquoted escaped trailing whitespace",
			value: `Amazon\ `,
			want:  "Amazon ",
		},
		{
			name:  "unquoted escaped shell characters",
			value: `price=\$5\;stable`,
			want:  "price=$5;stable",
		},
		{
			name:  "double quoted value",
			value: `"Amazon Linux"`,
			want:  "Amazon Linux",
		},
		{
			name:  "double quoted shell escapes",
			value: "\"quote=\\\" dollar=\\$ backtick=\\` slash=\\\\\"",
			want:  "quote=\" dollar=$ backtick=` slash=\\",
		},
		{
			name:  "double quoted non-special escape remains literal",
			value: `"literal\n"`,
			want:  `literal\n`,
		},
		{
			name:  "single quoted value is literal",
			value: `'Amazon $Linux \path'`,
			want:  `Amazon $Linux \path`,
		},
		{
			name:  "single quoted escaped apostrophe",
			value: `'Vendor'\''s Linux'`,
			want:  `Vendor's Linux`,
		},
		{
			name:  "surrounding whitespace remains accepted",
			value: "  \"Amazon Linux\"   ",
			want:  "Amazon Linux",
		},
		{
			name:  "trailing unquoted whitespace remains ignored",
			value: "Amazon   ",
			want:  "Amazon",
		},
		{
			name:    "unescaped whitespace",
			value:   "Amazon Linux",
			wantErr: true,
		},
		{
			name:    "trailing escape",
			value:   `Amazon\`,
			wantErr: true,
		},
		{
			name:    "lone double quote",
			value:   `"`,
			wantErr: true,
		},
		{
			name:    "unterminated double quote",
			value:   `"Amazon`,
			wantErr: true,
		},
		{
			name:    "unterminated single quote",
			value:   `'Amazon`,
			wantErr: true,
		},
		{
			name:    "escaped closing double quote without terminator",
			value:   `"Amazon\"`,
			wantErr: true,
		},
		{
			name:    "quoted concatenation",
			value:   `"Amazon"Linux`,
			wantErr: true,
		},
		{
			name:    "quote in unquoted value",
			value:   `Amazon"Linux"`,
			wantErr: true,
		},
		{
			name:    "unescaped variable expansion",
			value:   `Amazon$Linux`,
			wantErr: true,
		},
		{
			name:    "unescaped command substitution",
			value:   "Amazon`Linux`",
			wantErr: true,
		},
		{
			name:    "unescaped shell separator",
			value:   `Amazon;Linux`,
			wantErr: true,
		},
		{
			name:    "unescaped expansion in double quotes",
			value:   `"Amazon $Linux"`,
			wantErr: true,
		},
		{
			name:    "double-quoted invalid UTF-8",
			value:   string([]byte{'"', 'U', 0xff, '"'}),
			wantErr: true,
		},
		{
			name:    "unquoted invalid UTF-8",
			value:   string([]byte{'U', 0xff}),
			wantErr: true,
		},
		{
			name:    "escaped invalid UTF-8",
			value:   string([]byte{'U', '\\', 0xff}),
			wantErr: true,
		},
		{
			name:    "double-quoted control character",
			value:   "\"Ubuntu\x00\"",
			wantErr: true,
		},
		{
			name:    "single-quoted control character",
			value:   "'Ubuntu\x00'",
			wantErr: true,
		},
		{
			name:    "unquoted control character",
			value:   "Ubuntu\x1b",
			wantErr: true,
		},
		{
			name:    "escaped control character",
			value:   "Ubuntu\\\x00",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOSReleaseValue(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
