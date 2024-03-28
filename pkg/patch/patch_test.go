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
		osRelease []byte
		err       error
		osType    string
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
			BUG_REPORT_URL="https://bugs.debian.org/"`),
			err:    nil,
			osType: "debian",
		},
		{
			osRelease: nil,
			err:       errors.ErrUnsupported,
			osType:    "",
		},
	}

	for _, tc := range testCases {
		t.Run("TestGetOSType", func(t *testing.T) {
			osType, err := getOSType(context.TODO(), tc.osRelease)

			// Use testify package to assert that the output manifest and error match the expected ones
			assert.Equal(t, tc.osType, osType)
			assert.Equal(t, tc.err, err)
		})
	}
}
