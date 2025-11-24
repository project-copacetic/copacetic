package provenance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	log "github.com/sirupsen/logrus"
)

// Fetcher handles retrieving SLSA provenance attestations from container registries.
type Fetcher struct{}

// NewFetcher creates a new provenance fetcher.
func NewFetcher() *Fetcher {
	return &Fetcher{}
}

// FetchAttestation attempts to fetch SLSA provenance for the given image reference.
func (f *Fetcher) FetchAttestation(ctx context.Context, imageRef string) (*Attestation, error) {
	log.Debugf("Attempting to fetch SLSA provenance for %s", imageRef)

	// Parse image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference %s: %w", imageRef, err)
	}

	// Fetch attestations using cosign - try all SLSA predicate types
	slsaTypes := []string{
		"https://slsa.dev/provenance/v1",
		"https://slsa.dev/provenance/v0.2",
		"https://slsa.dev/provenance/v0.1",
		"", // empty string to get all attestations
	}

	for _, predicateType := range slsaTypes {
		attestations, err := cosign.FetchAttestationsForReference(ctx, ref, predicateType, ociremote.WithRemoteOptions())
		if err != nil {
			log.Debugf("Failed to fetch attestations with predicate type %s: %v", predicateType, err)
			continue
		}

		if len(attestations) == 0 {
			continue
		}

		// Parse the first attestation
		for _, att := range attestations {
			// Decode base64 payload
			payloadBytes, err := base64.StdEncoding.DecodeString(att.PayLoad)
			if err != nil {
				log.Debugf("Failed to decode attestation payload: %v", err)
				continue
			}

			parsed, err := f.parseAttestation(payloadBytes)
			if err != nil {
				log.Debugf("Failed to parse attestation: %v", err)
				continue
			}

			if parsed != nil && isSLSAProvenance(parsed.PredicateType) {
				log.Infof("Successfully fetched SLSA provenance for %s (level: %d, type: %s)",
					imageRef, parsed.SLSALevel, parsed.PredicateType)
				return parsed, nil
			}
		}
	}

	return nil, fmt.Errorf("no SLSA provenance found for %s", imageRef)
}

// parseAttestation parses an attestation payload into our Attestation structure.
func (f *Fetcher) parseAttestation(payload []byte) (*Attestation, error) {
	// Parse as in-toto statement
	var statement intoto.Statement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
	}

	// Parse predicate
	var predicate map[string]any
	if statement.Predicate != nil {
		predicateJSON, err := json.Marshal(statement.Predicate)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal predicate: %w", err)
		}
		if err := json.Unmarshal(predicateJSON, &predicate); err != nil {
			return nil, fmt.Errorf("failed to unmarshal predicate: %w", err)
		}
	}

	attestation := &Attestation{
		Statement:     &statement,
		Predicate:     predicate,
		PredicateType: statement.PredicateType,
		SLSALevel:     inferSLSALevel(&statement, predicate),
	}

	return attestation, nil
}

// isSLSAProvenance checks if a predicate type is SLSA provenance.
func isSLSAProvenance(predicateType string) bool {
	slsaTypes := []string{
		"https://slsa.dev/provenance/v0.1",
		"https://slsa.dev/provenance/v0.2",
		"https://slsa.dev/provenance/v1",
		"https://slsa.dev/provenance/v1.0",
	}

	for _, t := range slsaTypes {
		if predicateType == t {
			return true
		}
	}
	return false
}

// inferSLSALevel attempts to infer the SLSA level from the provenance.
// This is a simplified heuristic - full verification would require more analysis.
func inferSLSALevel(statement *intoto.Statement, predicate map[string]any) int {
	// Check for builder information
	if predicate == nil {
		return 0
	}

	// SLSA v1.0 structure
	if runDetails, ok := predicate["runDetails"].(map[string]any); ok {
		if builder, ok := runDetails["builder"].(map[string]any); ok {
			if builderID, ok := builder["id"].(string); ok && builderID != "" {
				// If we have a builder ID, assume at least level 2
				return 2
			}
		}
	}

	// SLSA v0.2 structure
	if builder, ok := predicate["builder"].(map[string]any); ok {
		if builderID, ok := builder["id"].(string); ok && builderID != "" {
			return 2
		}
	}

	// If we have materials/dependencies, assume level 1
	if materials, ok := predicate["materials"].([]any); ok && len(materials) > 0 {
		return 1
	}

	return 0
}
