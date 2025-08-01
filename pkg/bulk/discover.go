package bulk

import (
	"fmt"
	"sort"

	"github.com/Masterminds/semver"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	log "github.com/sirupsen/logrus"
)

func FindTagsToPatch(spec *ImageSpec) ([]string, error) {
	log.Infof("Discovering tags for '%s' with strategy: %s", spec.Name, spec.Tags.Strategy)

	repo, err := name.NewRepository(spec.Image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository name '%s': %w", spec.Image, err)
	}

	switch spec.Tags.Strategy {
	case "list":
		return findTagsByList(repo, spec.Tags.List), nil
	case "pattern":
		return findTagsByPattern(repo, spec)
	case "latest":
		return findTagsByLatest(repo, spec)
	}

	return nil, fmt.Errorf("internal error: unhandled strategy '%s'", spec.Tags.Strategy)
}

// Filter by list.
func findTagsByList(repo name.Repository, list []string) []string {
	log.Debugf("Using explicit list of tags for '%s': %v", repo.Name(), list)
	return list
}

// Filter by latest.
func findTagsByLatest(repo name.Repository, spec *ImageSpec) ([]string, error) {
	allTags, err := listAllTags(repo)
	if err != nil {
		return nil, err
	}

	filteredTags := excludeTags(allTags, spec.Tags.Exclude)

	versions := make([]*semver.Version, 0, len(filteredTags))
	for _, t := range filteredTags {
		v, err := semver.NewVersion(t)
		if err == nil {
			versions = append(versions, v)
		} else {
			log.Warnf("Could not parse tag '%s' as semver for '%s', skipping", t, repo.Name())
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
		if err == nil {
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

func listAllTags(repo name.Repository) ([]string, error) {
	tags, err := remote.List(repo)
	if err != nil {
		return nil, fmt.Errorf("failed to list tags for repository '%s': %w", repo.Name(), err)
	}
	return tags, nil
}

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
