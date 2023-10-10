package v1alpha1

import (
	"encoding/json"
	"fmt"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

func ConvertV1alpha1UpdateManifestToUnversionedUpdateManifest(scannerOutput []byte) (*unversioned.UpdateManifest, error) {
	var um unversioned.UpdateManifest

	if err := json.Unmarshal(scannerOutput, &um); err != nil {
		return nil, fmt.Errorf("error parsing scanner output: %w", err)
	}

	return &um, nil
}
