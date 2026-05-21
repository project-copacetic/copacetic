package helm

import "strings"

// OverrideSpec defines a tag variant substitution for chart-discovered images.
// From and To are substrings of the image tag (e.g., From: "distroless-libc", To: "debian").
type OverrideSpec struct {
	From string
	To   string
}

// ApplyOverrides applies tag variant overrides to a list of chart-discovered images.
// The overrides map key is an image name pattern (e.g., "timberio/vector").
// Matching is performed as an exact key match first, then as a suffix match to
// handle images prefixed with a registry (e.g., "docker.io/timberio/vector").
// Returns a new slice with overrides applied (input is not mutated).
func ApplyOverrides(images []ChartImage, overrides map[string]OverrideSpec) []ChartImage {
	if images == nil {
		return nil
	}
	result := make([]ChartImage, 0, len(images))
	for _, img := range images {
		override, found := matchOverride(img.Repository, overrides)
		if found {
			result = append(result, applyOverride(img, override))
		} else {
			result = append(result, img)
		}
	}
	return result
}

// MatchRepositoryPattern checks if a repository matches a pattern key using
// exact match first, then suffix matching to handle registry prefixes.
// For example, pattern "nginx" matches repository "docker.io/library/nginx".
func MatchRepositoryPattern(repository, pattern string) bool {
	if repository == pattern {
		return true
	}
	return strings.HasSuffix(repository, "/"+pattern)
}

// matchOverride finds the override that applies to the given image repository.
// It tries an exact map key match first, then a suffix match to handle registry prefixes.
func matchOverride(repository string, overrides map[string]OverrideSpec) (OverrideSpec, bool) {
	if o, ok := overrides[repository]; ok {
		return o, true
	}
	for key, o := range overrides {
		if MatchRepositoryPattern(repository, key) {
			return o, true
		}
	}
	return OverrideSpec{}, false
}

// applyOverride performs the From/To substring replacement on the image tag.
// Only the first occurrence of From is replaced.
func applyOverride(img ChartImage, override OverrideSpec) ChartImage {
	return ChartImage{
		Repository: img.Repository,
		Tag:        strings.Replace(img.Tag, override.From, override.To, 1),
	}
}
