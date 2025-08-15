package common

import (
	"fmt"
	"strings"
)

// GetRepoNameWithDigest extracts repo name with digest from image name and digest.
// e.g. "docker.io/library/nginx:1.21.6-patched" -> "nginx@sha256:...".
func GetRepoNameWithDigest(patchedImageName, imageDigest string) string {
	parts := strings.Split(patchedImageName, "/")
	last := parts[len(parts)-1]
	if idx := strings.IndexRune(last, ':'); idx >= 0 {
		last = last[:idx]
	}
	nameWithDigest := fmt.Sprintf("%s@%s", last, imageDigest)
	return nameWithDigest
}
