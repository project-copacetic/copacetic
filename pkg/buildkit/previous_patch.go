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
// builders carry their own history. LLB clients that write no history get the
// same entries, so an image they build on a Copa output looks like a re-patch.
const exporterHistoryComment = "buildkit.exporter.image.v0"

// imageLayersConfig holds the image config fields that describe its layers.
type imageLayersConfig struct {
	RootFS  specs.RootFS    `json:"rootfs"`
	History []specs.History `json:"history,omitempty"`
}

// patchLayers says how an image's layers relate to the base image a
// BaseImage or origin label names.
type patchLayers int

const (
	// patchLayersNotOnBase: the image's layers do not start with the base's
	// layers, or cannot be compared with them.
	patchLayersNotOnBase patchLayers = iota
	// patchLayersDerived: the image is built on the base, but has layers above
	// it that a Copa patch did not add, as an image built FROM a Copa output does.
	patchLayersDerived
	// patchLayersCopaOutput: the image is the base's layers followed only by
	// layers the image exporter added for a patch.
	patchLayersCopaOutput
)

// classifyPatchLayers reports whether inputConfig describes an image Copa
// produced from baseConfig. A first patch can add several layers and a
// re-patch adds one, so the number of added layers is not checked. The error
// explains any other result.
func classifyPatchLayers(inputConfig, baseConfig []byte) (patchLayers, error) {
	var input, base imageLayersConfig
	if err := json.Unmarshal(inputConfig, &input); err != nil {
		return patchLayersNotOnBase, fmt.Errorf("parse image config: %w", err)
	}
	if err := json.Unmarshal(baseConfig, &base); err != nil {
		return patchLayersNotOnBase, fmt.Errorf("parse base image config: %w", err)
	}
	if input.RootFS.Type != "layers" || base.RootFS.Type != "layers" {
		return patchLayersNotOnBase, errors.New("its layers cannot be compared with the base image's layers")
	}
	inputLayers, baseLayers := input.RootFS.DiffIDs, base.RootFS.DiffIDs
	if len(inputLayers) < len(baseLayers) || !slices.Equal(inputLayers[:len(baseLayers)], baseLayers) {
		return patchLayersNotOnBase, errors.New("its layers do not start with the base image's layers")
	}
	if len(inputLayers) == len(baseLayers) {
		return patchLayersCopaOutput, nil
	}

	// BuildKit gives every layer of an exported image a history entry, so a
	// history that does not line up with the layers was rewritten by another tool.
	var layerHistory []specs.History
	for _, entry := range input.History {
		if !entry.EmptyLayer {
			layerHistory = append(layerHistory, entry)
		}
	}
	if len(layerHistory) != len(inputLayers) {
		return patchLayersDerived, errors.New("its history does not describe each of its layers")
	}
	for i, entry := range layerHistory[len(baseLayers):] {
		if entry.Comment != exporterHistoryComment {
			return patchLayersDerived, fmt.Errorf("layer %d above the base image's layers was not added by a Copa patch", i+1)
		}
	}
	return patchLayersCopaOutput, nil
}

// topLayerAddedByBuild reports whether the top layer of the image config was
// added by the build that produced the image rather than by a Copa patch: its
// history describes each layer, and the top layer's entry is not one the image
// exporter added.
func topLayerAddedByBuild(config []byte) bool {
	var image imageLayersConfig
	if err := json.Unmarshal(config, &image); err != nil || len(image.RootFS.DiffIDs) == 0 {
		return false
	}
	var layerHistory []specs.History
	for _, entry := range image.History {
		if !entry.EmptyLayer {
			layerHistory = append(layerHistory, entry)
		}
	}
	return len(layerHistory) == len(image.RootFS.DiffIDs) && layerHistory[len(layerHistory)-1].Comment != exporterHistoryComment
}

// imageConfigWithBaseImage returns the config in document with its BaseImage
// label set to locator and any origin labels removed, so labels inherited
// through FROM cannot describe the output.
func imageConfigWithBaseImage(document *imageConfigLabelsDocument, locator string) ([]byte, error) {
	document.labels["BaseImage"] = locator
	for _, key := range []string{types.AnnotationPatchOriginKind, types.AnnotationPatchOriginName, types.AnnotationPatchOriginDigest} {
		delete(document.labels, key)
	}
	return document.marshal()
}
