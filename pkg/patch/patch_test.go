package patch

import (
	"context"
	"errors"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestRemoveIfNotDebug(t *testing.T) {
	// Test removing working folder when not in debug mode
	t.Run("RemoveWorkingFolder", func(t *testing.T) {
		// Set log level to Info to simulate not being in debug mode
		log.SetLevel(log.InfoLevel)

		// Create a temporary working folder
		workingFolder := t.TempDir()
		defer os.RemoveAll(workingFolder)

		removeIfNotDebug(workingFolder)

		// Check that the working folder was removed
		if _, err := os.Stat(workingFolder); err == nil {
			t.Errorf("Working folder should have been removed but still exists")
		}
	})

	// Test not removing working folder when in debug mode
	t.Run("KeepWorkingFolderDebug", func(t *testing.T) {
		// Set log level to Debug to simulate being in debug mode
		log.SetLevel(log.DebugLevel)

		// Create a temporary working folder
		workingFolder := t.TempDir()

		removeIfNotDebug(workingFolder)

		// Check that the working folder still exists
		if _, err := os.Stat(workingFolder); err != nil {
			t.Errorf("Working folder should have been kept but was removed")
		}

		// Clean up the working folder manually
		os.RemoveAll(workingFolder)
	})
}

func TestGetOSType(t *testing.T) {
	testCases := []struct {
		osRelease      []byte
		err            error
		expectedOSType string
	}{
		{
			osRelease: []byte(`PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
			NAME="Debian GNU/Linux"
			VERSION_ID="11"
			VERSION="11 (bullseye)"
			VERSION_CODENAME=bullseye
			ID=debian
			HOME_URL="https://www.debian.org/"
			SUPPORT_URL="https://www.debian.org/support"
			BUG_REPORT_URL="https://bugs.debian.org/"
			`),
			err:            nil,
			expectedOSType: "debian",
		},
		{
			osRelease: []byte(`NAME="Alpine Linux"
			ID=alpine
			VERSION_ID=3.7.3
			PRETTY_NAME="Alpine Linux v3.7"
			HOME_URL="http://alpinelinux.org"
			BUG_REPORT_URL="http://bugs.alpinelinux.org"`),
			err:            nil,
			expectedOSType: "alpine",
		},
		{
			osRelease: []byte(`PRETTY_NAME="Ubuntu 22.04.4 LTS"
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
			UBUNTU_CODENAME=jammy`),
			err:            nil,
			expectedOSType: "ubuntu",
		},
		{
			osRelease: []byte(`NAME="Amazon Linux"
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
			SUPPORT_END="2028-03-15"`),
			err:            nil,
			expectedOSType: "amazon",
		},
		{
			osRelease: []byte(`NAME="CentOS Linux"
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
			CENTOS_MANTISBT_PROJECT_VERSION="8"`),
			err:            nil,
			expectedOSType: "centos",
		},
		{
			osRelease: []byte(`NAME="Common Base Linux Mariner"
			VERSION="2.0.20240117"
			ID=mariner
			VERSION_ID="2.0"
			PRETTY_NAME="CBL-Mariner/Linux"
			ANSI_COLOR="1;34"
			HOME_URL="https://aka.ms/cbl-mariner"
			BUG_REPORT_URL="https://aka.ms/cbl-mariner"
			SUPPORT_URL="https://aka.ms/cbl-mariner"`),
			err:            nil,
			expectedOSType: "cbl-mariner",
		},
		{
			osRelease: []byte(`NAME="Red Hat Enterprise Linux"
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
			REDHAT_SUPPORT_PRODUCT_VERSION="8.9"`),
			err:            nil,
			expectedOSType: "redhat",
		},
		{
			osRelease: []byte(`NAME="Rocky Linux"
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
			REDHAT_SUPPORT_PRODUCT_VERSION="9.3"`),
			err:            nil,
			expectedOSType: "rocky",
		},
		{
			osRelease:      nil,
			err:            errors.ErrUnsupported,
			expectedOSType: "",
		},
	}

	for _, tc := range testCases {
		t.Run("TestGetOSType", func(t *testing.T) {
			osType, err := getOSType(context.TODO(), tc.osRelease)

			// Use testify package to assert that the output manifest and error match the expected ones
			assert.Equal(t, tc.expectedOSType, osType)
			assert.Equal(t, tc.err, err)
		})
	}
}
