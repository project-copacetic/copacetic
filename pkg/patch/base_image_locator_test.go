package patch

import (
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/stretchr/testify/require"
)

// Multi-platform children record the supplied locator in BaseImage, except a
// locally inspected index, whose child Copa has always named by digest there.
func TestMultiPlatformBaseImageLocator(t *testing.T) {
	child := "registry.example.com/team/app@" + digest.FromString("child").String()
	index := digest.FromString("index").String()
	for _, tc := range []struct {
		image, want string
	}{
		{"registry.example.com/team/app", "registry.example.com/team/app"},
		{"registry.example.com/team/app:1.0", "registry.example.com/team/app:1.0"},
		{"registry.example.com/team/app:1.0@" + index, "registry.example.com/team/app:1.0@" + index},
		{"alpine:3.20", "docker.io/library/alpine:3.20"},
	} {
		t.Run(tc.image, func(t *testing.T) {
			registry := &buildkit.ImageSource{Name: tc.image, Registry: true}
			require.Equal(t, tc.want, multiPlatformBaseImageLocator(tc.image, registry, child))
			local := &buildkit.ImageSource{Name: tc.image}
			require.Equal(t, child, multiPlatformBaseImageLocator(tc.image, local, child))
		})
	}
}
