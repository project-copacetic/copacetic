package buildkit

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	specs "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/project-copacetic/copacetic/pkg/types"
)

// exporterHistoryComment marks the history entries BuildKit's image exporter
// (and Docker's) adds for layers the exported image config does not describe.
// Copa exports the config of the image it patches, so every layer a Copa patch
// adds gets one of these entries. Layers added by a Dockerfile or most other
// builders carry their own history.
const exporterHistoryComment = "buildkit.exporter.image.v0"

// imageLayersConfig holds the image config fields that describe its layers.
type imageLayersConfig struct {
	RootFS  specs.RootFS    `json:"rootfs"`
	History []specs.History `json:"history,omitempty"`
}

// verifyPreviousPatchLayers checks that inputConfig describes an image Copa
// produced from baseConfig: the base image's layers, followed only by layers
// the image exporter added for a patch. A first patch can add several layers
// and a re-patch adds one, so the number of added layers is not checked. An
// image built FROM a Copa output inherits its labels, but has its own layers on
// top, and an image whose layers do not start with the base was not built on it.
func verifyPreviousPatchLayers(inputConfig, baseConfig []byte) error {
	var input, base imageLayersConfig
	if err := json.Unmarshal(inputConfig, &input); err != nil {
		return fmt.Errorf("parse image config: %w", err)
	}
	if err := json.Unmarshal(baseConfig, &base); err != nil {
		return fmt.Errorf("parse base image config: %w", err)
	}
	if input.RootFS.Type != "layers" || base.RootFS.Type != "layers" {
		return errors.New("its layers cannot be compared with the base image's layers")
	}
	inputLayers, baseLayers := input.RootFS.DiffIDs, base.RootFS.DiffIDs
	if len(inputLayers) < len(baseLayers) || !slices.Equal(inputLayers[:len(baseLayers)], baseLayers) {
		return errors.New("its layers do not start with the base image's layers")
	}
	if len(inputLayers) == len(baseLayers) {
		return nil
	}

	var layerHistory []specs.History
	for _, entry := range input.History {
		if !entry.EmptyLayer {
			layerHistory = append(layerHistory, entry)
		}
	}
	if len(layerHistory) != len(inputLayers) {
		return errors.New("its history does not describe each of its layers")
	}
	for i, entry := range layerHistory[len(baseLayers):] {
		if entry.Comment != exporterHistoryComment {
			return fmt.Errorf("layer %d above the base image's layers was not added by a Copa patch", i+1)
		}
	}
	return nil
}

// suppliedImageConfig returns the config of an image patched as supplied. Its
// BaseImage label names the supplied image, and inherited origin labels are
// dropped so they cannot describe the output.
func suppliedImageConfig(document *imageConfigLabelsDocument, locator string) ([]byte, error) {
	document.labels["BaseImage"] = locator
	for _, key := range []string{types.AnnotationPatchOriginKind, types.AnnotationPatchOriginName, types.AnnotationPatchOriginDigest} {
		delete(document.labels, key)
	}
	return document.marshal()
}
