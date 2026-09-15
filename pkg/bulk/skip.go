package bulk

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/report"
	log "github.com/sirupsen/logrus"
)

// skipCheckResult encapsulates the decision about whether to skip patching an image.
type skipCheckResult struct {
	ShouldSkip  bool
	Reason      string
	ResolvedTag string // The tag to use if NOT skipping (versioned)
}

// isArchSpecificTag reports whether tag is an architecture-specific variant of baseTag
// (e.g. "3.18.0-patched-386" for baseTag "3.18.0-patched").
// It checks against the suffixes derived from Copa's validPlatforms list.
func isArchSpecificTag(tag, baseTag string) bool {
	for _, suffix := range patch.ArchTagSuffixes() {
		if tag == baseTag+"-"+suffix {
			return true
		}
	}
	return false
}

// discoverExistingPatchTags lists all tags in the repository that match the base tag pattern.
// It returns tags matching either "<baseTag>" or "<baseTag>-N" where N is a number.
// Architecture-specific tags (e.g. "<baseTag>-386") are excluded.
func discoverExistingPatchTags(repo, baseTag string) ([]string, error) {
	repository, err := name.NewRepository(repo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repository name '%s': %w", repo, err)
	}

	allTags, err := listAllTags(repository)
	if err != nil {
		// Fail-open: if we can't list tags, proceed with base tag
		log.Warnf("Failed to list tags for repository '%s': %v", repo, err)
		return []string{}, nil
	}

	// Escape special regex characters in the base tag
	escapedBase := regexp.QuoteMeta(baseTag)
	// Match either the exact base tag or base tag followed by -N
	pattern := fmt.Sprintf("^%s(?:-([0-9]+))?$", escapedBase)
	re := regexp.MustCompile(pattern)

	var matching []string
	for _, tag := range allTags {
		if re.MatchString(tag) && !isArchSpecificTag(tag, baseTag) {
			matching = append(matching, tag)
		}
	}

	// Sort by version number (ascending)
	sort.Slice(matching, func(i, j int) bool {
		verI := extractVersionNumber(matching[i], baseTag)
		verJ := extractVersionNumber(matching[j], baseTag)
		return verI < verJ
	})

	return matching, nil
}

// extractVersionNumber extracts the version number from a tag.
// Returns 0 for the base tag, N for base-N tags.
func extractVersionNumber(tag, baseTag string) int {
	if tag == baseTag {
		return 0
	}
	// Extract the number after the last dash
	parts := strings.Split(tag, "-")
	if len(parts) > 0 {
		if num, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
			return num
		}
	}
	return 0
}

// latestPatchTag returns the tag with the highest version number from the list.
func latestPatchTag(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	// Tags are already sorted by version number, so return the last one
	return tags[len(tags)-1]
}

// nextPatchTag computes the next version tag to use for re-patching.
func nextPatchTag(baseTag string, existingTags []string) string {
	if len(existingTags) == 0 {
		return baseTag
	}

	maxVersion := 0
	for _, tag := range existingTags {
		ver := extractVersionNumber(tag, baseTag)
		if ver > maxVersion {
			maxVersion = ver
		}
	}

	return fmt.Sprintf("%s-%d", baseTag, maxVersion+1)
}

// reportIndex maps normalized image references to report file paths.
type reportIndex struct {
	refs map[string]string // normalized ref → file path
}

// buildReportIndex scans a flat directory for JSON report files, extracts ArtifactName
// from each, normalizes references, and builds a lookup map.
// Note: Only top-level JSON files are indexed; subdirectories are not scanned recursively.
func buildReportIndex(reportsDir string) *reportIndex {
	idx := &reportIndex{
		refs: make(map[string]string),
	}

	// Read all files in the directory
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		log.Warnf("Failed to read reports directory '%s': %v", reportsDir, err)
		return idx
	}

	// Process each JSON file
	for _, entry := range entries {
		if entry.IsDir() {
			log.Debugf("Skipping subdirectory '%s' in reports directory (only top-level JSON files are indexed)", entry.Name())
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(reportsDir, entry.Name())

		// Read the file and extract ArtifactName
		data, err := os.ReadFile(filePath) // #nosec G304 - filePath is from controlled directory scan
		if err != nil {
			log.Debugf("Failed to read report file '%s': %v", filePath, err)
			continue
		}

		// Lightweight unmarshal to extract just ArtifactName
		var reportData struct {
			ArtifactName string `json:"ArtifactName"`
		}
		if err := json.Unmarshal(data, &reportData); err != nil {
			log.Debugf("Failed to parse JSON from '%s': %v", filePath, err)
			continue
		}

		if reportData.ArtifactName == "" {
			log.Debugf("Report file '%s' has no ArtifactName field, skipping", filePath)
			continue
		}

		// Normalize the ArtifactName reference
		normalizedRef := reportData.ArtifactName
		if ref, err := name.ParseReference(reportData.ArtifactName); err == nil {
			normalizedRef = ref.Name()
		} else {
			log.Debugf("Failed to normalize reference '%s', using raw value: %v", reportData.ArtifactName, err)
		}

		// Store in the index
		idx.refs[normalizedRef] = filePath
		log.Debugf("Indexed report: %s -> %s (from ArtifactName: %s)", normalizedRef, filePath, reportData.ArtifactName)
	}

	log.Infof("Built report index with %d entries from '%s'", len(idx.refs), reportsDir)
	return idx
}

// lookup finds a report for the given image reference by normalizing it
// and checking the index.
func (idx *reportIndex) lookup(imageRef string) (string, bool) {
	if idx == nil || idx.refs == nil {
		return "", false
	}

	// Normalize the incoming imageRef
	normalizedRef := imageRef
	if ref, err := name.ParseReference(imageRef); err == nil {
		normalizedRef = ref.Name()
	} else {
		log.Debugf("Failed to normalize lookup reference '%s', using raw value: %v", imageRef, err)
	}

	// Look up in the index
	path, found := idx.refs[normalizedRef]
	return path, found
}

// checkReportForVulnerabilities parses a vulnerability report file to check for fixable vulnerabilities.
// Returns (hasVulns, error) where:
// - hasVulns=true means fixable vulnerabilities were found.
// - error is set if the report couldn't be parsed.
var checkReportForVulnerabilities = func(reportPath, scanner, pkgTypes, libraryPatchLevel string) (bool, error) {
	// Use existing report parsing from pkg/report
	updateManifest, err := report.TryParseScanReport(reportPath, scanner, pkgTypes, libraryPatchLevel)
	if err != nil {
		return false, fmt.Errorf("failed to parse report: %w", err)
	}

	// Check if there are any updates (fixable vulnerabilities)
	hasUpdates := len(updateManifest.OSUpdates) > 0 || len(updateManifest.LangUpdates) > 0
	return hasUpdates, nil
}

// evaluatePatchAction orchestrates the full workflow: discover existing tags, check report if needed, and decide whether to patch.
func evaluatePatchAction(repo, baseTag, scanner string, reports *reportIndex, pkgTypes, libraryPatchLevel string) skipCheckResult {
	// Discover existing patched tags
	existingTags, err := discoverExistingPatchTags(repo, baseTag)
	if err != nil {
		// Fail-open: if we can't discover tags, proceed with patching
		log.Warnf("Failed to discover existing tags for '%s': %v. Proceeding with patch.", repo, err)
		return skipCheckResult{
			ShouldSkip:  false,
			ResolvedTag: baseTag,
		}
	}

	// If no existing patched tags, proceed with base tag
	if len(existingTags) == 0 {
		log.Debugf("No existing patched tags found for '%s', proceeding with base tag '%s'", repo, baseTag)
		return skipCheckResult{
			ShouldSkip:  false,
			ResolvedTag: baseTag,
		}
	}

	// Compute the next version tag
	nextTag := nextPatchTag(baseTag, existingTags)

	// If no reports index provided, fail-open and proceed to patch
	if reports == nil {
		log.Debugf("No reports index provided, proceeding with patch for '%s'", repo)
		return skipCheckResult{
			ShouldSkip:  false,
			ResolvedTag: nextTag,
		}
	}

	// Get the latest existing tag to check
	latestTag := latestPatchTag(existingTags)
	imageRef := fmt.Sprintf("%s:%s", repo, latestTag)

	// Look up the report using the index
	reportPath, found := reports.lookup(imageRef)
	if !found {
		// Report not found, fail-open and proceed to patch
		log.Debugf("No report found for image '%s' in index, proceeding with patch (fail-open)", imageRef)
		return skipCheckResult{
			ShouldSkip:  false,
			ResolvedTag: nextTag,
		}
	}

	log.Debugf("Checking vulnerability report '%s' for image '%s'", reportPath, imageRef)
	hasVulns, err := checkReportForVulnerabilities(reportPath, scanner, pkgTypes, libraryPatchLevel)
	if err != nil {
		// Fail-open: if report parsing fails, proceed with patching
		log.Warnf("Failed to parse report '%s': %v. Proceeding with patch (fail-open).", reportPath, err)
		return skipCheckResult{
			ShouldSkip:  false,
			ResolvedTag: nextTag,
		}
	}

	if !hasVulns {
		// No fixable vulnerabilities, skip patching
		log.Debugf("No fixable vulnerabilities found in report for '%s', skipping patch", imageRef)
		return skipCheckResult{
			ShouldSkip:  true,
			Reason:      "no fixable vulnerabilities",
			ResolvedTag: latestTag,
		}
	}

	// Vulnerabilities found, proceed with patching using next version tag
	log.Debugf("Fixable vulnerabilities found in report for '%s', re-patching with tag '%s'", imageRef, nextTag)
	return skipCheckResult{
		ShouldSkip:  false,
		ResolvedTag: nextTag,
	}
}
