package ocilayout

import (
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFullImageSelectorsRespectRepository(t *testing.T) {
	for _, test := range []struct {
		name          string
		selector      string
		targetName    string
		includeTarget bool
		wantError     string
	}{
		{name: "missing repository", selector: "nginx:latest", wantError: "unavailable"},
		{name: "familiar name", selector: "nginx:latest", targetName: "docker.io/library/nginx:latest", includeTarget: true},
		{name: "normalized name", selector: "docker.io/library/nginx:latest", targetName: "nginx:latest", includeTarget: true},
		{name: "untagged repository", selector: "nginx:latest", targetName: "docker.io/library/nginx", includeTarget: true},
		{name: "tag alias in same repository", selector: "nginx:latest", targetName: "docker.io/library/nginx:old", includeTarget: true},
		{name: "bare tag stays ambiguous", selector: "latest", targetName: "docker.io/library/nginx:latest", includeTarget: true, wantError: "2 descriptors"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			other := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "amd64"}, map[string]string{
				annotationImageName:       "docker.io/library/alpine:latest",
				ocispec.AnnotationRefName: "latest",
			}, nil)
			target := newImageManifest(t, root, &ocispec.Platform{OS: "linux", Architecture: "arm64"}, map[string]string{
				annotationImageName:       test.targetName,
				ocispec.AnnotationRefName: "latest",
			}, nil)
			descriptors := []ocispec.Descriptor{other}
			if test.includeTarget {
				descriptors = append(descriptors, target)
			}
			fixture := newLayoutAt(t, root, descriptors)
			source, err := Open(t.Context(), fixture.path, "", test.selector)
			if test.wantError != "" {
				require.ErrorContains(t, err, test.wantError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, target.Digest, source.Descriptor.Digest)
		})
	}
}
