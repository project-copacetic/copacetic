package buildkit

import (
	"fmt"
	"maps"

	"github.com/distribution/reference"
	"github.com/project-copacetic/copacetic/pkg/types"
)

// MergeImageSourceAnnotations combines descriptor and manifest metadata without
// allowing either surface to complete or overwrite an invalid origin claim.
// Manifest annotation values take precedence after both claims are validated.
func MergeImageSourceAnnotations(descriptor, manifest map[string]string) (map[string]string, error) {
	var origin *types.SourceLineage
	for _, annotations := range []map[string]string{descriptor, manifest} {
		_, kind := annotations[types.AnnotationPatchOriginKind]
		_, name := annotations[types.AnnotationPatchOriginName]
		_, dgst := annotations[types.AnnotationPatchOriginDigest]
		if !kind && !name && !dgst {
			continue
		}
		current := types.SourceLineageFromAnnotations(annotations)
		if !current.Valid() {
			return nil, fmt.Errorf("invalid patch origin annotation tuple")
		}
		if origin != nil {
			if origin.Kind != current.Kind || origin.Digest != current.Digest {
				return nil, fmt.Errorf("source descriptor origin contradicts manifest origin")
			}
			namesMatch := origin.Name == current.Name
			if origin.Kind == types.PatchOriginImage {
				left, _ := reference.ParseNormalizedNamed(origin.Name)
				right, _ := reference.ParseNormalizedNamed(current.Name)
				namesMatch = left.Name() == right.Name()
			}
			if !namesMatch {
				return nil, fmt.Errorf("source descriptor origin repository contradicts manifest origin")
			}
		}
		origin = current
	}
	annotations := maps.Clone(descriptor)
	if annotations == nil {
		annotations = map[string]string{}
	}
	maps.Copy(annotations, manifest)
	return annotations, nil
}
