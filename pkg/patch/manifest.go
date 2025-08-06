package patch

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/buildx/util/imagetools"
	"github.com/docker/cli/cli/config"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	log "github.com/sirupsen/logrus"

	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

const (
	copaAnnotationKeyPrefix = "sh.copa"
)

// createMultiPlatformManifest assembles a multi-platform manifest list and pushes it
// via Buildx's imagetools helper (equivalent to
// `docker buildx imagetools create --tag … img@sha256:d1 img@sha256:d2 …`).
func createMultiPlatformManifest(
	ctx context.Context,
	imageName reference.NamedTagged,
	items []types.PatchResult,
	originalImage string,
) error {
	resolver := imagetools.New(imagetools.Opt{
		Auth: config.LoadDefaultConfigFile(os.Stderr),
	})

	// fetch annotations from the original image
	annotations := make(map[exptypes.AnnotationKey]string)

	// get the original image index manifest annotations
	originalAnnotations, err := utils.GetIndexManifestAnnotations(ctx, originalImage)
	if err != nil {
		log.Warnf("Failed to get original image annotations: %v", err)
		// Even if we fail to get original annotations, we should add Copa annotations
		createdKey := exptypes.AnnotationKey{
			Type: exptypes.AnnotationIndex,
			Key:  "org.opencontainers.image.created",
		}
		annotations[createdKey] = time.Now().UTC().Format(time.RFC3339)

		// Add Copa-specific annotation at index level
		copaKey := exptypes.AnnotationKey{
			Type: exptypes.AnnotationIndex,
			Key:  copaAnnotationKeyPrefix + ".patched",
		}
		annotations[copaKey] = time.Now().UTC().Format(time.RFC3339)
	} else {
		log.Infof("Retrieved %d annotations from original image %s", len(originalAnnotations), originalImage)
		if len(originalAnnotations) > 0 {
			// copy all annotations from the original image
			for k, v := range originalAnnotations {
				// create an AnnotationKey for index level annotations
				ak := exptypes.AnnotationKey{
					Type: exptypes.AnnotationIndex,
					Key:  k,
				}
				annotations[ak] = v
			}

			// update annotations that should reflect the patched state
			// update the created timestamp to reflect when the patch was applied
			createdKey := exptypes.AnnotationKey{
				Type: exptypes.AnnotationIndex,
				Key:  "org.opencontainers.image.created",
			}
			annotations[createdKey] = time.Now().UTC().Format(time.RFC3339)

			// if theres a version annotation, update it to reflect the patched tag
			versionKey := exptypes.AnnotationKey{
				Type: exptypes.AnnotationIndex,
				Key:  "org.opencontainers.image.version",
			}
			if version, ok := annotations[versionKey]; ok {
				// Extract the tag from the patched image name to determine what suffix to use
				patchedTag := imageName.Tag()

				// Try to determine what was added to the original version
				// If the patched tag contains the original version, extract the suffix
				if strings.Contains(patchedTag, version) {
					// Use the full patched tag as the new version
					annotations[versionKey] = patchedTag
				} else {
					// Fallback: append the patched tag as a suffix
					annotations[versionKey] = version + "-" + patchedTag
				}
			}

			log.Debugf("Preserving %d annotations from original image", len(annotations))
		} else {
			log.Info("No annotations found in original image, adding Copa annotations only")
			// add Copa-specific annotations even if there are no original annotations
			createdKey := exptypes.AnnotationKey{
				Type: exptypes.AnnotationIndex,
				Key:  "org.opencontainers.image.created",
			}
			annotations[createdKey] = time.Now().UTC().Format(time.RFC3339)
		}
	}

	// Always ensure we have Copa-specific annotation at index level
	copaKey := exptypes.AnnotationKey{
		Type: exptypes.AnnotationIndex,
		Key:  copaAnnotationKeyPrefix + ".patched",
	}
	annotations[copaKey] = time.Now().UTC().Format(time.RFC3339)

	// add manifest descriptor level annotations for each platform
	for _, it := range items {
		if it.PatchedDesc != nil && it.PatchedDesc.Platform != nil {
			// use annotations that are already preserved in PatchedDesc.Annotations
			// this works for both patched and pass-through platforms
			if len(it.PatchedDesc.Annotations) > 0 {
				// add each annotation as a manifest-descriptor annotation
				for k, v := range it.PatchedDesc.Annotations {
					ak := exptypes.AnnotationKey{
						Type:     exptypes.AnnotationManifestDescriptor,
						Platform: it.PatchedDesc.Platform,
						Key:      k,
					}
					// for patched platforms, update creation timestamp to reflect patching
					// for other platforms, preserve original timestamps
					if k == "org.opencontainers.image.created" && it.PatchedRef != it.OriginalRef {
						// this is a patched platform, update the timestamp
						annotations[ak] = time.Now().UTC().Format(time.RFC3339)
					} else {
						// this is a platform with preserved or non-timestamp annotation
						annotations[ak] = v
					}
				}
				log.Infof("Added %d manifest-descriptor annotations for platform %s", len(it.PatchedDesc.Annotations), fmt.Sprintf("%s/%s", it.PatchedDesc.Platform.OS, it.PatchedDesc.Platform.Architecture))
				for k, v := range it.PatchedDesc.Annotations {
					log.Debugf("Platform %s annotation: %s = %s", fmt.Sprintf("%s/%s", it.PatchedDesc.Platform.OS, it.PatchedDesc.Platform.Architecture), k, v)
				}
			}
		}
	}

	// Source references (repo@sha256:digest) – one per architecture.
	srcRefs := make([]*imagetools.Source, 0, len(items))
	for _, it := range items {
		if it.PatchedDesc == nil {
			return fmt.Errorf("patched descriptor is nil for %s", it.OriginalRef.String())
		}

		srcRefs = append(srcRefs, &imagetools.Source{
			Ref:  it.PatchedRef,
			Desc: *it.PatchedDesc,
		})
	}

	log.Infof("Creating manifest list with %d annotations and %d sources", len(annotations), len(srcRefs))
	for ak, v := range annotations {
		log.Debugf("Index annotation: %s = %s", ak.Key, v)
	}

	idxBytes, desc, err := resolver.Combine(ctx, srcRefs, annotations, false)
	if err != nil {
		return fmt.Errorf("failed to combine sources into manifest list: %w", err)
	}

	log.Infof("Successfully created manifest list, pushing to %s", imageName.String())
	err = resolver.Push(ctx, imageName, desc, idxBytes)
	if err != nil {
		return fmt.Errorf("failed to push multi-platform manifest list: %w", err)
	}

	log.Infof("Successfully pushed multi-platform manifest list to %s", imageName.String())
	return nil
}
