package v1alpha1

import (
	"encoding/json"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

// ConvertV1alpha1UpdateManifestToUnversionedUpdateManifest converts a v1alpha1 UpdateManifest to an unversioned UpdateManifest.
func ConvertV1alpha1UpdateManifestToUnversionedUpdateManifest(data []byte) (*unversioned.UpdateManifest, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var v1alpha1Manifest UpdateManifest
	if err := json.Unmarshal(data, &v1alpha1Manifest); err != nil {
		return nil, err
	}

	// Convert v1alpha1 to unversioned format
	result := &unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    v1alpha1Manifest.Metadata.OS.Type,
				Version: v1alpha1Manifest.Metadata.OS.Version,
			},
			Config: unversioned.Config{
				Arch:    v1alpha1Manifest.Metadata.Config.Arch,
				Variant: "", // v1alpha1 doesn't have Variant field
			},
		},
		OSUpdates:   convertToUnversionedUpdatePackages(v1alpha1Manifest.Updates),
		LangUpdates: []unversioned.UpdatePackage{}, // v1alpha1 doesn't have separate language updates
	}

	return result, nil
}

func convertToUnversionedUpdatePackages(v1alpha1Updates UpdatePackages) unversioned.UpdatePackages {
	if v1alpha1Updates == nil {
		return nil
	}

	result := make(unversioned.UpdatePackages, len(v1alpha1Updates))
	for i, pkg := range v1alpha1Updates {
		result[i] = unversioned.UpdatePackage{
			Name:             pkg.Name,
			InstalledVersion: pkg.InstalledVersion,
			FixedVersion:     pkg.FixedVersion,
			VulnerabilityID:  pkg.VulnerabilityID,
			Type:             "", // v1alpha1 doesn't have Type/Class fields
			Class:            "",
		}
	}
	return result
}
