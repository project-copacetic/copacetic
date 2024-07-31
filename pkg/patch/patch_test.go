package patch

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"testing"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"

	"github.com/distribution/reference"

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

func TestGeneratePatchedTag(t *testing.T) {
	testCases := []struct {
		name                 string
		dockerImageName      string
		userSuppliedPatchTag string
		expectedPatchedTag   string
	}{
		{
			name:                 "NoTag_NoUserSupplied",
			dockerImageName:      "docker.io/library/alpine",
			userSuppliedPatchTag: "",
			expectedPatchedTag:   defaultPatchedTagSuffix,
		},
		{
			name:                 "WithTag_NoUserSupplied",
			dockerImageName:      "docker.io/redhat/ubi9:latest",
			userSuppliedPatchTag: "",
			expectedPatchedTag:   "latest-patched",
		},
		{
			name:                 "WithTag_UserSupplied",
			dockerImageName:      "docker.io/librari/ubuntu:jammy-20231004",
			userSuppliedPatchTag: "20231004-patched",
			expectedPatchedTag:   "20231004-patched",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			named, _ := reference.ParseNormalizedNamed(tc.dockerImageName)
			patchedTag := generatePatchedTag(named, tc.userSuppliedPatchTag)
			if patchedTag != tc.expectedPatchedTag {
				t.Errorf("expected patchedTag to be %s but got %s", tc.expectedPatchedTag, patchedTag)
			}
		})
	}
}

func TestUpdateManifest(t *testing.T) {
	errPkgs := []string{"package1", "package2", "package3"}

	updates := &unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    "Linux",
				Version: "5.0.1",
			},
			Config: unversioned.Config{
				Arch: "x86_64",
			},
		},
		Updates: []unversioned.UpdatePackage{
			{Name: "package1"},
			{Name: "package2"},
			{Name: "package3"},
		},
	}

	testCases := []struct {
		name     string
		updates  *unversioned.UpdateManifest
		errPkgs  []string
		expected *unversioned.UpdateManifest
	}{
		{
			name:    "NoErrorPackages",
			updates: updates,
			errPkgs: []string{},
			expected: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "Linux",
						Version: "5.0.1",
					},
					Config: unversioned.Config{
						Arch: "x86_64",
					},
				},
				Updates: []unversioned.UpdatePackage{
					{Name: "package1"},
					{Name: "package2"},
					{Name: "package3"},
				},
			},
		},
		{
			name:    "AllErrorPackages",
			updates: updates,
			errPkgs: errPkgs,
			expected: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "Linux",
						Version: "5.0.1",
					},
					Config: unversioned.Config{
						Arch: "x86_64",
					},
				},
				Updates: []unversioned.UpdatePackage{},
			},
		},
		{
			name:    "SomeErrorPackages",
			updates: updates,
			errPkgs: []string{"package1"},
			expected: &unversioned.UpdateManifest{
				Metadata: unversioned.Metadata{
					OS: unversioned.OS{
						Type:    "Linux",
						Version: "5.0.1",
					},
					Config: unversioned.Config{
						Arch: "x86_64",
					},
				},
				Updates: []unversioned.UpdatePackage{
					{Name: "package2"},
					{Name: "package3"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := updateManifest(tc.updates, tc.errPkgs)
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Errorf("TestUpdateManifest(%v, %v): expected %v, actual %v", tc.updates, tc.errPkgs, tc.expected, actual)
			}
		})
	}
}

func TestHandleError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{
			name:    "no error",
			err:     nil,
			wantErr: false,
		},
		{
			name:    "test error",
			err:     errors.New("test error"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan error, 1)
			defer close(ch)

			_, err := handleError(ch, tt.err)

			select {
			case chErr := <-ch:
				if (chErr == nil && tt.wantErr) || (chErr != nil && !tt.wantErr) {
					t.Errorf("Error channel did not return expected error, got: %v, want: %v", chErr, tt.err)
				}
			default:
				if tt.wantErr {
					t.Error("Expected handleError to send error to error channel but it did not")
				}
			}

			if (err == nil && tt.wantErr) || (err != nil && !tt.wantErr) {
				t.Errorf("handleError() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// define a mock reader
type mockReader struct {
	data []byte
	err  error
}

func (mr *mockReader) Read(p []byte) (int, error) {
	copy(p, mr.data)
	return len(mr.data), mr.err
}

func TestDockerLoad(t *testing.T) {
	ctx := context.TODO()

	testCases := []struct {
		name      string
		pipeR     io.Reader
		mockCmd   *exec.Cmd
		expectErr bool
	}{
		{
			name:      "Unrecognized image format",
			pipeR:     &mockReader{nil, errors.New("unrecognized image format")},
			mockCmd:   exec.Command("echo", "test"),
			expectErr: true,
		},
		{
			name:  "Invalid tar header",
			pipeR: &mockReader{[]byte("alpine:latest"), errors.New("unrecognized tar header")},
			// this command is likely to fail which is desired for this test case
			mockCmd:   exec.Command("docker", "load"),
			expectErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := dockerLoad(ctx, testCase.pipeR)
			if testCase.expectErr && err == nil {
				t.Errorf("expected an error but got none")
			}
			if !testCase.expectErr && err != nil {
				t.Errorf("did not expect an error but got %v", err)
			}
		})
	}
}
