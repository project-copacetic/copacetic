package v1alpha1

import (
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

func Convert_v1alpha1_UpdateManifest_To_unversioned_UpdateManifest(reportMap map[string]interface{}) (*unversioned.UpdateManifest, error) {
	var um unversioned.UpdateManifest = reportMap["report"].(unversioned.UpdateManifest)
	return &um, nil
}
