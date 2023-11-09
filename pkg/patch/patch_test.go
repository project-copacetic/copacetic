package patch

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
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

func TestPatchedImageTarget(t *testing.T) {
	tests := []struct {
		name       string
		image      string
		patchedTag string
		want       string
		wantErr    bool
	}{
		{
			name:       "tag passed is empty",
			image:      "docker.io/library/nginx:1.21.3",
			patchedTag: "",
			want:       "docker.io/library/nginx:1.21.3-patched",
			wantErr:    false,
		},

		{
			name:       "tag passed with value",
			image:      "docker.io/library/nginx:1.21.3",
			patchedTag: "custom",
			want:       "docker.io/library/nginx:custom",
			wantErr:    false,
		},
		{
			name:       "tag passed but without registry or repo",
			image:      "docker.io/library/nginx:1.21.3",
			patchedTag: "my.registry/nginx:1.21.3-patched",
			want:       "",
			wantErr:    true,
		},
		{
			name:       "tag passed contains registry, repo and image",
			image:      "docker.io/library/nginx:1.21.3",
			patchedTag: "my.registry.io/myrepo/nginx:1.21.3-patched",
			want:       "my.registry.io/myrepo/nginx:1.21.3-patched",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := patchedImageTarget(tt.image, tt.patchedTag)
			if (err != nil) != tt.wantErr {
				t.Errorf("patchedImageTarget() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				if *got != tt.want {
					t.Errorf("patchedImageTarget() = %v, want %v", *got, tt.want)
				}
			}
		})
	}
}
