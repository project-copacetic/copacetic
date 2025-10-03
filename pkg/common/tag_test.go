package common

import (
	"testing"

	"github.com/distribution/reference"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePatchedTag(t *testing.T) {
	tests := []struct {
		name        string
		imageRef    string
		explicitTag string
		suffix      string
		want        string
		wantErr     bool
		errContains string
	}{
		{
			name:        "Explicit tag wins",
			imageRef:    "myimage:v1.0",
			explicitTag: "custom-tag",
			suffix:      "patched",
			want:        "custom-tag",
		},
		{
			name:        "Default suffix when none provided",
			imageRef:    "myimage:v1.0",
			explicitTag: "",
			suffix:      "",
			want:        "v1.0-patched",
		},
		{
			name:        "Custom suffix",
			imageRef:    "myimage:latest",
			explicitTag: "",
			suffix:      "fixed",
			want:        "latest-fixed",
		},
		{
			name:        "Image with tag and custom suffix",
			imageRef:    "docker.io/library/ubuntu:22.04",
			explicitTag: "",
			suffix:      "security-update",
			want:        "22.04-security-update",
		},
		{
			name:        "No tag in image reference",
			imageRef:    "myimage",
			explicitTag: "",
			suffix:      "patched",
			wantErr:     true,
			errContains: "no tag found in image reference",
		},
		{
			name:        "No tag with digest only",
			imageRef:    "myimage@sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
			explicitTag: "",
			suffix:      "patched",
			wantErr:     true,
			errContains: "no tag found in image reference",
		},
		{
			name:        "Explicit tag with untagged image",
			imageRef:    "myimage",
			explicitTag: "v1.0-patched",
			suffix:      "unused",
			want:        "v1.0-patched",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the image reference
			ref, err := reference.ParseNormalizedNamed(tt.imageRef)
			require.NoError(t, err)

			// Call the function
			got, err := ResolvePatchedTag(ref, tt.explicitTag, tt.suffix)

			// Check results
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestResolvePatchedTag_ComplexReferences(t *testing.T) {
	tests := []struct {
		name        string
		imageRef    string
		explicitTag string
		suffix      string
		want        string
	}{
		{
			name:        "Registry with port",
			imageRef:    "localhost:5000/myimage:v1.0",
			explicitTag: "",
			suffix:      "patched",
			want:        "v1.0-patched",
		},
		{
			name:        "Long registry path",
			imageRef:    "gcr.io/my-project/subfolder/myimage:latest",
			explicitTag: "",
			suffix:      "updated",
			want:        "latest-updated",
		},
		{
			name:        "Numeric tag",
			imageRef:    "nginx:1.21.6",
			explicitTag: "",
			suffix:      "alpine",
			want:        "1.21.6-alpine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the image reference
			ref, err := reference.ParseNormalizedNamed(tt.imageRef)
			require.NoError(t, err)

			// Call the function
			got, err := ResolvePatchedTag(ref, tt.explicitTag, tt.suffix)

			// Check results
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolvePatchedImageName(t *testing.T) {
	tests := []struct {
		name        string
		imageRef    string
		explicitTag string
		suffix      string
		wantImage   string
		wantTag     string
		wantErr     bool
		errContains string
	}{
		{
			name:        "Default suffix when none provided",
			imageRef:    "myimage:v1.0",
			explicitTag: "",
			suffix:      "",
			wantImage:   "docker.io/library/myimage",
			wantTag:     "v1.0-patched",
		},
		{
			name:        "Explicit tag is just a tag",
			imageRef:    "myimage:v1.0",
			explicitTag: "custom-tag",
			suffix:      "patched",
			wantImage:   "docker.io/library/myimage",
			wantTag:     "custom-tag",
		},
		{
			name:        "Explicit tag is a full reference",
			imageRef:    "myimage:v1.0",
			explicitTag: "gcr.io/my-project/subfolder/myimage:custom-tag",
			suffix:      "",
			wantImage:   "gcr.io/my-project/subfolder/myimage",
			wantTag:     "custom-tag",
		},
		{
			name:        "Reference does not contain a tag",
			imageRef:    "myimage",
			explicitTag: "",
			suffix:      "",
			wantImage:   "",
			wantTag:     "",
			wantErr:     true,
			errContains: "failed to generate tag",
		},
		{
			name:        "Invalid explicit reference",
			imageRef:    "myimage:v1.0",
			explicitTag: "UPPERCASE:invalid",
			wantErr:     true,
			errContains: "failed to parse explicit reference",
		},
		{
			name:        "Explicit reference does not contain a tag",
			imageRef:    "myimage:v1.0",
			explicitTag: "localhost:5000/myimage",
			suffix:      "",
			wantImage:   "",
			wantTag:     "",
			wantErr:     true,
			errContains: "does not contain a tag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the image reference
			ref, err := reference.ParseNormalizedNamed(tt.imageRef)
			require.NoError(t, err)

			// Call the function
			image, tag, err := ResolvePatchedImageName(ref, tt.explicitTag, tt.suffix)

			// Check results
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantImage, image)
				assert.Equal(t, tt.wantTag, tag)
			}
		})
	}
}
