package patch

import (
	"context"
	"fmt"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/ocilayout"
	"github.com/project-copacetic/copacetic/pkg/types"
)

// copaPatchedAnnotation marks a manifest that Copa produced. Copa writes it on
// the patched manifest, and on its index descriptor for multi-platform output.
// An image built FROM a patched image does not inherit manifest annotations, so
// the marker identifies Copa's own output rather than derived applications.
// Config labels such as BaseImage are inherited by derived images and are
// deliberately not used for this check.
const copaPatchedAnnotation = copaAnnotationKeyPrefix + ".image.patched"

// rejectPatchedOCITargets refuses OCI layout input when a platform selected for
// patching is already a Copa output. Copa cannot recover the original image
// from a layout, so patching it again would stack a second patch layer. A
// report scanned from the patched image also omits the fixes it already
// contains, so it must not be reused against the original. Preserved platforms
// and index-level markers do not trigger the check.
func rejectPatchedOCITargets(ctx context.Context, source *ocilayout.Source, platforms []types.PatchPlatform) error {
	if source == nil {
		return nil
	}
	for i := range platforms {
		if platforms[i].ShouldPreserve {
			continue
		}
		platform := &platforms[i].Platform
		desc, err := source.PlatformDescriptor(ctx, platform)
		if err != nil {
			return err
		}
		location := ""
		if _, marked := desc.Annotations[copaPatchedAnnotation]; marked {
			location = "descriptor"
		} else {
			manifestAnnotations, err := source.PlatformAnnotations(ctx, platform)
			if err != nil {
				return err
			}
			if _, marked := manifestAnnotations[copaPatchedAnnotation]; marked {
				location = "manifest"
			}
		}
		if location == "" {
			continue
		}
		return fmt.Errorf(
			"OCI layout image %s for platform %s was already patched by Copa (%s annotation %s); re-patching a patched layout is not supported. "+
				"Patch the original, unpatched layout instead, and rescan that original image rather than reusing a report scanned from the patched image, "+
				"which omits the fixes the patched image already contains",
			desc.Digest, buildkit.FormatPlatform(*platform), location, copaPatchedAnnotation,
		)
	}
	return nil
}
