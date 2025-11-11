package bulk

import (
	"fmt"
	"sort"

	"github.com/Masterminds/semver/v3"
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

	filteredTags := excludeTags(allTags, spec.Tags.Exclude)

	versions := make([]*semver.Version, 0, len(filteredTags))
	for _, t := range filteredTags {
		v, err := semver.NewVersion(t)
		if err == nil && v.Prerelease() == "" {
			versions = append(versions, v)
		} else {
			log.Warnf("Could not parse tag '%s' as stable semver for '%s', skipping", t, repo.Name())
		}
	}

	if len(versions) == 0 {
		log.Warnf("No valid semver tags found for '%s' to determine 'latest'", spec.Name)
		return []string{}, nil
	}

	sort.Sort(semver.Collection(versions))

	latestTag := versions[len(versions)-1].Original()
	log.Debugf("Found 'latest' tag for '%s': %s", spec.Name, latestTag)
	return []string{latestTag}, nil
}

// findTagsByPattern filters tags based on a regular expression pattern.
func findTagsByPattern(repo name.Repository, spec *ImageSpec) ([]string, error) {
	allTags, err := listAllTags(repo)
	if err != nil {
		return nil, err
	}

	// Filter by regex pattern.
	matchingTags := []string{}
	for _, tag := range allTags {
		if spec.Tags.compiledPattern.MatchString(tag) {
			matchingTags = append(matchingTags, tag)
		}
	}

	// Filter by exclusion list.
	matchingTags = excludeTags(matchingTags, spec.Tags.Exclude)

	versions := make([]*semver.Version, 0, len(matchingTags))
	for _, t := range matchingTags {
		v, err := semver.NewVersion(t)
		if err == nil && v.Prerelease() == "" {
			versions = append(versions, v)
		} else {
			log.Warnf("Could not parse tag '%s' as semver for '%s', skipping", t, repo.Name())
		}
	}

	if len(versions) == 0 {
		log.Warnf("No valid semver tags found for '%s' after applying pattern", spec.Name)
		return []string{}, nil
	}

	// Sort from oldest to newest.
	sort.Sort(semver.Collection(versions))

	if spec.Tags.MaxTags > 0 && len(versions) > spec.Tags.MaxTags {
		versions = versions[len(versions)-spec.Tags.MaxTags:]
	}

	finalTags := make([]string, len(versions))
	for i, v := range versions {
		finalTags[i] = v.Original()
	}

	log.Debugf("Found tags for '%s' by pattern: %v", spec.Name, finalTags)
	return finalTags, nil
}

// listAllTags is a function variable that can be overridden for testing purposes.
var listAllTags = func(repo name.Repository) ([]string, error) {
	tags, err := remote.List(repo)
	if err != nil {
		return nil, fmt.Errorf("failed to list tags for repository '%s': %w", repo.Name(), err)
	}
	return tags, nil
}

// excludeTags removes tags from a given list that are present in the exclusions list.
func excludeTags(tags, exclusions []string) []string {
	if len(exclusions) == 0 {
		return tags
	}

	exclusionSet := make(map[string]struct{}, len(exclusions))
	for _, ex := range exclusions {
		exclusionSet[ex] = struct{}{}
	}

	result := []string{}
	for _, tag := range tags {
		if _, found := exclusionSet[tag]; !found {
			result = append(result, tag)
		}
	}
	return result
}
