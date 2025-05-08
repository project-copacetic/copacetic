package patch

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	buildkitclient "github.com/moby/buildkit/client"
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

	t.Run("RemoveWorkingFolderWhenLogLevelIsInfo", func(t *testing.T) {
		log.SetLevel(log.InfoLevel)
		workingFolder := t.TempDir()

		removeIfNotDebug(workingFolder)

		// folder should be removed
		if _, err := os.Stat(workingFolder); err == nil {
			t.Errorf("working folder should have been removed but still exists at: %s", workingFolder)
		}
	})

	t.Run("KeepWorkingFolderWhenLogLevelIsDebug", func(t *testing.T) {
		log.SetLevel(log.DebugLevel)
		workingFolder := t.TempDir()

		removeIfNotDebug(workingFolder)

		// folder should remain
		if _, err := os.Stat(workingFolder); err != nil {
			t.Errorf("working folder should have been kept but was removed at: %s", workingFolder)
		}
	})

	t.Run("NoopWhenFolderDoesNotExist", func(t *testing.T) {
		log.SetLevel(log.InfoLevel)
		// create then remove
		workingFolder := t.TempDir()
		os.RemoveAll(workingFolder)

		removeIfNotDebug(workingFolder)

		// still doesn't exist, and no panic
		if _, err := os.Stat(workingFolder); err == nil {
			t.Errorf("folder unexpectedly re-created: %s", workingFolder)
		}
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
			osRelease: []byte(`NAME="Microsoft Azure Linux"
			VERSION="3.0.20240727"
			ID=azurelinux
			VERSION_ID="3.0"
			PRETTY_NAME="Microsoft Azure Linux 3.0"
			ANSI_COLOR="1;34"
			HOME_URL="https://aka.ms/azurelinux"
			BUG_REPORT_URL="https://aka.ms/azurelinux"
			SUPPORT_URL="https://aka.ms/azurelinux"`),
			err:            nil,
			expectedOSType: "azurelinux",
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
			osRelease: []byte(`NAME="Oracle Linux Server"
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
			ORACLE_SUPPORT_PRODUCT_VERSION=7.9`),
			err:            nil,
			expectedOSType: "oracle",
		},
		{
			osRelease: []byte(`NAME="Oracle Linux Server"
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
			ORACLE_SUPPORT_PRODUCT_VERSION=8.9`),
			err:            nil,
			expectedOSType: "oracle",
		},
		{
			osRelease:      nil,
			err:            errors.ErrUnsupported,
			expectedOSType: "",
		},
		{
			osRelease: []byte(`NAME="AlmaLinux"
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
			REDHAT_SUPPORT_PRODUCT_VERSION="9.4"`),
			err:            nil,
			expectedOSType: "alma",
		},
		{
			osRelease: []byte(`PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
			NAME="Debian GNU/Linux"
			VERSION_ID="11"
			`),
			err:            nil,
			expectedOSType: "debian",
		},
		{
			osRelease: []byte(`NAME="Alpine Linux"
			ID=alpine
			VERSION_ID=3.7.3`),
			err:            nil,
			expectedOSType: "alpine",
		},
		{
			osRelease: []byte(`NAME="SomeRandomOS"
			ID=someos
			VERSION_ID=1.0`),
			err:            errors.ErrUnsupported,
			expectedOSType: "",
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

func TestGetOSVersion(t *testing.T) {
	testCases := []struct {
		osRelease         []byte
		errMsg            string
		expectedOSVersion string
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
			errMsg:            "",
			expectedOSVersion: "11",
		},
		{
			osRelease:         []byte("Cannot Parse Version_ID"),
			errMsg:            "unable to parse os-release data osrelease: malformed line \"Cannot Parse Version_ID\"",
			expectedOSVersion: "",
		},
		{
			osRelease: []byte(`PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
			VERSION_ID="11"
			ID=debian`),
			errMsg:            "",
			expectedOSVersion: "11",
		},
		{
			osRelease:         []byte("Cannot Parse Version_ID"),
			errMsg:            `unable to parse os-release data osrelease: malformed line "Cannot Parse Version_ID"`,
			expectedOSVersion: "",
		},
	}

	for _, tc := range testCases {
		t.Run("TestGetOSVersion", func(t *testing.T) {
			osVersion, err := getOSVersion(context.TODO(), tc.osRelease)

			var errMsg string
			if err == nil {
				errMsg = ""
			} else {
				errMsg = err.Error()
			}

			// Use testify package to assert that the output manifest and error match the expected ones
			assert.Equal(t, tc.expectedOSVersion, osVersion)
			assert.Equal(t, tc.errMsg, errMsg)
		})
	}
}

func TestGetRepoNameWithDigest(t *testing.T) {
	result := getRepoNameWithDigest("docker.io/library/nginx:1.21.6-patched", "sha256:mocked-digest")
	if result != "nginx@sha256:mocked-digest" {
		t.Fatalf("unexpected result: %s", result)
	}
	t.Run("WithTagAndDigest", func(t *testing.T) {
		result := getRepoNameWithDigest("docker.io/library/nginx:1.21.6-patched", "sha256:mocked-digest")
		assert.Equal(t, "nginx@sha256:mocked-digest", result)
	})

	t.Run("NoTagUsesFullImageName", func(t *testing.T) {
		result := getRepoNameWithDigest("docker.io/library/nginx", "sha256:abc123")
		// there's no trailing :tag, so we strip library/ prefix -> "nginx@sha256:abc123"
		assert.Equal(t, "nginx@sha256:abc123", result)
	})

	t.Run("RandomLocalImageName", func(t *testing.T) {
		result := getRepoNameWithDigest("localhost:5000/repo/image:mytag", "sha256:abcdef1234")
		// last portion is "image:mytag" => we only keep "image" for the name portion
		assert.Equal(t, "image@sha256:abcdef1234", result)
	})

	t.Run("NoRegistryNoTag", func(t *testing.T) {
		result := getRepoNameWithDigest("myimage", "sha256:short")
		// no registry, no tag, just "myimage" => name is "myimage@sha256:short"
		assert.Equal(t, "myimage@sha256:short", result)
	})
}

func TestResolvePatchedTag(t *testing.T) {
	tests := []struct {
		name        string
		image       string
		explicitTag string
		suffix      string
		want        string
		wantErr     bool
	}{
		{
			name:  "no explicitTag, no suffix, existing base tag",
			image: "docker.io/library/nginx:1.23",
			want:  "1.23-patched",
		},
		{
			name:    "no explicitTag, no suffix, no base tag",
			image:   "docker.io/library/nginx",
			wantErr: true,
		},
		{
			name:   "explicitTag overrides suffix and base tag",
			image:  "docker.io/library/nginx:1.23",
			suffix: "xyz",
			// user sets an explicit tag, so we don't append the suffix
			explicitTag: "my-funky-tag",
			want:        "my-funky-tag",
		},
		{
			name:   "custom suffix with base tag",
			image:  "docker.io/library/nginx:1.23",
			suffix: "security",
			want:   "1.23-security",
		},
		{
			name:    "custom suffix with no base tag",
			image:   "docker.io/library/nginx",
			suffix:  "foo",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// tags should always resolve here
			imageRef, err := reference.ParseNormalizedNamed(tc.image)
			if err != nil {
				t.Fatalf("failed to parse image reference: %v", err)
			}

			got, err := resolvePatchedTag(imageRef, tc.explicitTag, tc.suffix)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func init() {
	bkNewClient = func(ctx context.Context, _ buildkit.Opts) (*buildkitclient.Client, error) {
		// a path that certainly does not have a BuildKit daemon listening.
		return buildkitclient.New(ctx, "unix:///tmp/nowhere.sock")
	}
}

func TestPatch_BuildReturnsNilResponse(t *testing.T) {
	err := Patch(
		context.Background(),
		30*time.Second,
		"alpine:3.19", "", "", "", "", "", "", "", "", "",
		false, true,
		buildkit.Opts{},
	)

	if err == nil {
		t.Fatalf("expected error from Build(), got nil")
	}

	if !strings.Contains(err.Error(), "dial unix /tmp/nowhere.sock: connect: no such file or directory") {
		t.Fatalf("unexpected error from Build(): %v", err)
	}

	t.Logf("Patch returned error as expected (and did not panic): %v", err)
}
