package bulk

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	log "github.com/sirupsen/logrus"
)

const (
	StrategyList    = "list"
	StrategyPattern = "pattern"
	StrategyLatest  = "latest"
)

// FindTagsToPatch discovers image tags based on the specified strategy in the ImageSpec.
func FindTagsToPatch(spec *ImageSpec) ([]string, error) {
	log.Infof("Discovering tags for '%s' with strategy: %s", spec.Name, spec.Tags.Strategy)

	repo, err := name.NewRepository(spec.Image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository name '%s': %w", spec.Image, err)
	}

	switch spec.Tags.Strategy {
	case StrategyList:
		return findTagsByList(repo, spec.Tags.List), nil
	// StrategyPattern uses a regex pattern to match tags and can optionally limit the number of tags.
	case StrategyPattern:
		return findTagsByPattern(repo, spec)
	// StrategyLatest finds the latest semver-compliant tag, excluding pre-releases.

	case StrategyLatest:
		return findTagsByLatest(repo, spec)
	}

	return nil, fmt.Errorf("internal error: unhandled strategy '%s'", spec.Tags.Strategy)
}

// findTagsByList filters tags based on an explicit list provided in the configuration.
func findTagsByList(repo name.Repository, list []string) []string {
	log.Debugf("Using explicit list of tags for '%s': %v", repo.Name(), list)
	return list
}

// findTagsByLatest finds the latest semver-compliant tag for a given repository.
func findTagsByLatest(repo name.Repository, spec *ImageSpec) ([]string, error) {
	allTags, err := listAllTags(repo)
	if err != nil {
		return nil, err
	}

	exclusions := stringSet(spec.Tags.Exclude)
	var latest tagVersion
	found := false
	for _, t := range allTags {
		if _, excluded := exclusions[t]; excluded {
			continue
		}
		v, ok := parseStableTagVersion(t)
		if !ok {
			log.Warnf("Could not parse tag '%s' as stable semver for '%s', skipping", t, repo.Name())
			continue
		}
		if !found || compareTagVersions(v, latest) > 0 {
			latest = v
			found = true
		}
	}

	if !found {
		log.Warnf("No valid semver tags found for '%s' to determine 'latest'", spec.Name)
		return []string{}, nil
	}

	log.Debugf("Found 'latest' tag for '%s': %s", spec.Name, latest.original)
	return []string{latest.original}, nil
}

// findTagsByPattern filters tags based on a regular expression pattern.
func findTagsByPattern(repo name.Repository, spec *ImageSpec) ([]string, error) {
	allTags, err := listAllTags(repo)
	if err != nil {
		return nil, err
	}

	exclusions := stringSet(spec.Tags.Exclude)
	versions := make([]tagVersion, 0, len(allTags))
	for _, tag := range allTags {
		if _, excluded := exclusions[tag]; excluded {
			continue
		}
		if !spec.Tags.compiledPattern.MatchString(tag) {
			continue
		}
		v, ok := parseStableTagVersion(tag)
		if !ok {
			log.Warnf("Could not parse tag '%s' as semver for '%s', skipping", tag, repo.Name())
			continue
		}
		versions = append(versions, v)
	}

	if len(versions) == 0 {
		log.Warnf("No valid semver tags found for '%s' after applying pattern", spec.Name)
		return []string{}, nil
	}

	// Sort from oldest to newest.
	sort.Slice(versions, func(i, j int) bool {
		return compareTagVersions(versions[i], versions[j]) < 0
	})

	if spec.Tags.MaxTags > 0 && len(versions) > spec.Tags.MaxTags {
		versions = versions[len(versions)-spec.Tags.MaxTags:]
	}

	finalTags := make([]string, len(versions))
	for i, v := range versions {
		finalTags[i] = v.original
	}

	log.Debugf("Found tags for '%s' by pattern: %v", spec.Name, finalTags)
	return finalTags, nil
}

// listAllTags is a function variable that can be overridden for testing purposes.
var listAllTags = func(repo name.Repository) ([]string, error) {
	tags, err := remote.List(repo, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("failed to list tags for repository '%s': %w", repo.Name(), err)
	}
	return tags, nil
}

func stringSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, item := range items {
		set[item] = struct{}{}
	}
	return set
}

type tagVersion struct {
	original string
	major    uint64
	minor    uint64
	patch    uint64
}

func parseStableTagVersion(tag string) (tagVersion, bool) {
	if v, ok := parseSimpleStableTagVersion(tag); ok {
		return v, true
	}

	v, err := semver.NewVersion(tag)
	if err != nil || v.Prerelease() != "" {
		return tagVersion{}, false
	}
	return tagVersion{
		original: v.Original(),
		major:    v.Major(),
		minor:    v.Minor(),
		patch:    v.Patch(),
	}, true
}

func parseSimpleStableTagVersion(tag string) (tagVersion, bool) {
	firstDot := strings.IndexByte(tag, '.')
	if firstDot <= 0 {
		return tagVersion{}, false
	}
	secondDotRel := strings.IndexByte(tag[firstDot+1:], '.')
	if secondDotRel <= 0 {
		return tagVersion{}, false
	}
	secondDot := firstDot + 1 + secondDotRel
	if secondDot == len(tag)-1 {
		return tagVersion{}, false
	}

	major, ok := parseSemverNumber(tag[:firstDot])
	if !ok {
		return tagVersion{}, false
	}
	minor, ok := parseSemverNumber(tag[firstDot+1 : secondDot])
	if !ok {
		return tagVersion{}, false
	}
	patch, ok := parseSemverNumber(tag[secondDot+1:])
	if !ok {
		return tagVersion{}, false
	}

	return tagVersion{original: tag, major: major, minor: minor, patch: patch}, true
}

func parseSemverNumber(s string) (uint64, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	var n uint64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		digit := uint64(r - '0')
		if n > (^uint64(0)-digit)/10 {
			return 0, false
		}
		n = n*10 + digit
	}
	return n, true
}

func compareTagVersions(a, b tagVersion) int {
	if a.major != b.major {
		if a.major < b.major {
			return -1
		}
		return 1
	}
	if a.minor != b.minor {
		if a.minor < b.minor {
			return -1
		}
		return 1
	}
	if a.patch != b.patch {
		if a.patch < b.patch {
			return -1
		}
		return 1
	}
	return 0
}
