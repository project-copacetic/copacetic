package v1alpha2

import (
	"encoding/json"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

// ConvertV1alpha2UpdateManifestToUnversionedUpdateManifest converts a v1alpha2 UpdateManifest to an unversioned UpdateManifest.
func ConvertV1alpha2UpdateManifestToUnversionedUpdateManifest(data []byte) (*unversioned.UpdateManifest, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var v1alpha2Manifest UpdateManifest
	if err := json.Unmarshal(data, &v1alpha2Manifest); err != nil {
		return nil, err
	}

	// Convert v1alpha2 to unversioned format
	result := &unversioned.UpdateManifest{
		Metadata: unversioned.Metadata{
			OS: unversioned.OS{
				Type:    v1alpha2Manifest.Metadata.OS.Type,
				Version: v1alpha2Manifest.Metadata.OS.Version,
			},
			Config: unversioned.Config{
				Arch:    v1alpha2Manifest.Metadata.Config.Arch,
				Variant: v1alpha2Manifest.Metadata.Config.Variant,
			},
		},
		OSUpdates:   convertToUnversionedUpdatePackages(v1alpha2Manifest.OSUpdates),
		LangUpdates: convertLangToUnversionedUpdatePackages(v1alpha2Manifest.LangUpdates),
	}

	return result, nil
}

func convertToUnversionedUpdatePackages(v1alpha2Updates UpdatePackages) unversioned.UpdatePackages {
	if v1alpha2Updates == nil {
		return nil
	}

	result := make(unversioned.UpdatePackages, len(v1alpha2Updates))
	for i, pkg := range v1alpha2Updates {
		result[i] = unversioned.UpdatePackage{
			Name:             pkg.Name,
			InstalledVersion: pkg.InstalledVersion,
			FixedVersion:     pkg.FixedVersion,
			VulnerabilityID:  pkg.VulnerabilityID,
			Type:             pkg.Type,
			Class:            pkg.Class,
		}
	}
	return result
}

func convertLangToUnversionedUpdatePackages(v1alpha2LangUpdates LangUpdatePackages) []unversioned.UpdatePackage {
	if v1alpha2LangUpdates == nil {
		return nil
	}

	result := make([]unversioned.UpdatePackage, len(v1alpha2LangUpdates))
	for i, pkg := range v1alpha2LangUpdates {
		result[i] = unversioned.UpdatePackage{
			Name:             pkg.Name,
			InstalledVersion: pkg.InstalledVersion,
			FixedVersion:     pkg.FixedVersion,
			VulnerabilityID:  pkg.VulnerabilityID,
			Type:             pkg.Type,
			Class:            pkg.Class,
		}
	}
	return result
}
