package frontend

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/pkg/errors"

	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

// Scanner defines the interface for vulnerability scanners
type Scanner interface {
	// GetName returns the scanner name
	GetName() string
	
	// CanScanImage returns true if the scanner can scan the given image
	CanScanImage(image string) bool
	
	// ParseReport parses a vulnerability report into the standard format
	ParseReport(reportData []byte) (*unversioned.UpdateManifest, error)
	
	// ScanImage scans an image and returns vulnerability data (for future use)
	ScanImage(ctx context.Context, client gwclient.Client, image llb.State) (*unversioned.UpdateManifest, error)
}

// ScannerFactory creates scanner instances
type ScannerFactory struct {
	scanners map[string]Scanner
}

// NewScannerFactory creates a new scanner factory with default scanners
func NewScannerFactory() *ScannerFactory {
	factory := &ScannerFactory{
		scanners: make(map[string]Scanner),
	}
	
	// Register default scanners
	factory.RegisterScanner(&TrivyScanner{})
	factory.RegisterScanner(&GrypeScanner{})
	
	return factory
}

// RegisterScanner registers a scanner implementation
func (f *ScannerFactory) RegisterScanner(scanner Scanner) {
	f.scanners[scanner.GetName()] = scanner
}

// GetScanner returns a scanner by name
func (f *ScannerFactory) GetScanner(name string) (Scanner, error) {
	scanner, exists := f.scanners[name]
	if !exists {
		return nil, fmt.Errorf("scanner not found: %s", name)
	}
	return scanner, nil
}

// ListScanners returns available scanner names
func (f *ScannerFactory) ListScanners() []string {
	names := make([]string, 0, len(f.scanners))
	for name := range f.scanners {
		names = append(names, name)
	}
	return names
}

// TrivyScanner implements Scanner for Trivy
type TrivyScanner struct {
	version    string
	offlineMode bool
}

func (t *TrivyScanner) GetName() string {
	return "trivy"
}

func (t *TrivyScanner) CanScanImage(image string) bool {
	// Trivy can scan most container images
	return true
}

func (t *TrivyScanner) ParseReport(reportData []byte) (*unversioned.UpdateManifest, error) {
	// For now, assume the report is already in the correct format
	// In a full implementation, we'd convert from Trivy's JSON format
	var manifest unversioned.UpdateManifest
	if err := json.Unmarshal(reportData, &manifest); err != nil {
		return nil, errors.Wrap(err, "failed to parse trivy report")
	}
	return &manifest, nil
}

func (t *TrivyScanner) ScanImage(ctx context.Context, client gwclient.Client, image llb.State) (*unversioned.UpdateManifest, error) {
	// TODO: Implement live scanning with Trivy within BuildKit
	// For now, this is a placeholder for future enhancement
	return nil, errors.New("live scanning not yet implemented - use pre-generated reports")
}

// GrypeScanner implements Scanner for Grype
type GrypeScanner struct {
	version    string
	offlineMode bool
}

func (g *GrypeScanner) GetName() string {
	return "grype"
}

func (g *GrypeScanner) CanScanImage(image string) bool {
	// Grype can scan most container images
	return true
}

func (g *GrypeScanner) ParseReport(reportData []byte) (*unversioned.UpdateManifest, error) {
	// For now, assume the report is already in the correct format
	// In a full implementation, we'd convert from Grype's JSON format
	var manifest unversioned.UpdateManifest
	if err := json.Unmarshal(reportData, &manifest); err != nil {
		return nil, errors.Wrap(err, "failed to parse grype report")
	}
	return &manifest, nil
}

func (g *GrypeScanner) ScanImage(ctx context.Context, client gwclient.Client, image llb.State) (*unversioned.UpdateManifest, error) {
	// TODO: Implement live scanning with Grype within BuildKit
	// For now, this is a placeholder for future enhancement
	return nil, errors.New("live scanning not yet implemented - use pre-generated reports")
}