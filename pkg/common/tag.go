package common

import (
	"fmt"
	"strings"

	"github.com/distribution/reference"
)

// ResolvePatchedTag merges explicit tag & suffix rules, returning the final patched tag.
func ResolvePatchedTag(imageRef reference.Named, explicitTag, suffix string) (string, error) {
	// if user explicitly sets a final tag, that wins outright
	if explicitTag != "" {
		return explicitTag, nil
	}

	// parse out any existing tag from the image ref
	var baseTag string
	if tagged, ok := imageRef.(reference.Tagged); ok {
		baseTag = tagged.Tag()
	}

	// if suffix is empty, default to "patched"
	if suffix == "" {
		suffix = "patched"
	}

	// if we have no original baseTag (the user's image had no tag),
	// then we can't append a suffix to it
	if baseTag == "" {
		return "", fmt.Errorf("no tag found in image reference %s", imageRef.String())
	}

	// otherwise, combine them
	return fmt.Sprintf("%s-%s", baseTag, suffix), nil
}

// ResolvePatchedImageName merges with suffix rules or uses the explicitTag entirely, returning the final patched image name and tag.
func ResolvePatchedImageName(imageRef reference.Named, explicitTag, suffix string) (imageName, patchTag string, err error) {
	// Case 1: No explicit tag provided - generate one using suffix
	if explicitTag == "" {
		patchTag, err = ResolvePatchedTag(imageRef, explicitTag, suffix)
		if err != nil {
			return "", "", fmt.Errorf("failed to generate tag: %w", err)
		}

		return imageRef.Name(), patchTag, nil
	}

	// Check if explicitTag is a full reference (contains ":" or "@") or just a tag
	isFullReference := strings.Contains(explicitTag, ":") || strings.Contains(explicitTag, "@")

	if !isFullReference {
		// Case 2: explicitTag is just a tag (e.g., "0.1.0-1")
		return imageRef.Name(), explicitTag, nil
	}

	// Case 3: explicitTag is a full reference (contains ":" or "@")
	explicitRef, err := reference.ParseNormalizedNamed(explicitTag)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse explicit reference %s: %w", explicitTag, err)
	}

	// Extract tag from the full reference
	if taggedRef, ok := explicitRef.(reference.NamedTagged); ok {
		return explicitRef.Name(), taggedRef.Tag(), nil
	}

	return "", "", fmt.Errorf("explicit reference %s does not contain a tag", explicitTag)
}
