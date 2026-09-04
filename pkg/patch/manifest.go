package patch

import (
	"context"
	"fmt"
	"maps"
	"os"
	"time"

	"github.com/distribution/reference"
	"github.com/docker/buildx/util/imagetools"
	"github.com/docker/cli/cli/config"
	"github.com/moby/buildkit/exporter/containerimage/exptypes"
	"github.com/moby/buildkit/session/auth/authprovider"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"

	"github.com/project-copacetic/copacetic/pkg/types"
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
	originalAnnotations map[string]string,
	indexLineage *types.SourceLineage,
) error {
	resolver := imagetools.New(imagetools.Opt{
		Auth: authprovider.LoadAuthConfig(config.LoadDefaultConfigFile(os.Stderr)),
	})

	indexAnnotations := multiPlatformIndexAnnotations(imageName, originalAnnotations, indexLineage, time.Now().UTC())
	annotations := make(map[exptypes.AnnotationKey]string, len(indexAnnotations))
	for key, value := range indexAnnotations {
		annotations[exptypes.AnnotationKey{Type: exptypes.AnnotationIndex, Key: key}] = value
	}

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

	idxBytes, desc, _, err := resolver.Combine(ctx, srcRefs, annotations, false, nil)
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

func multiPlatformIndexAnnotations(
	imageName reference.NamedTagged,
	originalAnnotations map[string]string,
	indexLineage *types.SourceLineage,
	created time.Time,
) map[string]string {
	annotations := maps.Clone(originalAnnotations)
	if annotations == nil {
		annotations = make(map[string]string)
	}

	// A copied pair may describe an ancestor of the current source. Newly
	// computed lineage wins, and an unknown pair is omitted rather than stale.
	delete(annotations, ispec.AnnotationBaseImageName)
	delete(annotations, ispec.AnnotationBaseImageDigest)
	if indexLineage.Valid() {
		annotations[ispec.AnnotationBaseImageName] = indexLineage.Name
		annotations[ispec.AnnotationBaseImageDigest] = indexLineage.Digest.String()
	}

	now := created.UTC().Format(time.RFC3339)
	annotations[ispec.AnnotationCreated] = now
	annotations[copaAnnotationKeyPrefix+".patched"] = now
	if version, ok := annotations[ispec.AnnotationVersion]; ok {
		annotations[ispec.AnnotationVersion] = rewriteVersionAnnotation(version, imageName.Tag())
	}
	return annotations
}
