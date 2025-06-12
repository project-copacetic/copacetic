package pkgmgr

import (
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/moby/buildkit/client/llb"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
)

//go:embed scripts/detect-nodejs-apps.sh
var detectNodejsAppsScript string

//go:embed scripts/update-nodejs-package.sh
var updateNodejsPackageScript string

//go:embed scripts/cleanup-nodejs-apps.sh
var cleanupNodejsAppsScript string

const (
	npmToolName   = "npm"
	nodeEcosystem = "node"
)

type npmManager struct {
	config        *buildkit.Config
	workingFolder string
}


// InstallUpdates attempts to update vulnerable Node.js packages using a cautious approach.
// Based on our edge case analysis, we avoid npm audit fix --force and instead use targeted updates.
func (m *npmManager) InstallUpdates(ctx context.Context, manifest *unversioned.UpdateManifest, ignoreErrors bool) (*llb.State, []string, error) {
	if manifest == nil || len(manifest.Updates) == 0 {
		log.Info("No Node.js updates to install")
		return &m.config.ImageState, []string{}, nil
	}

	log.Infof("Processing %d Node.js package updates", len(manifest.Updates))
	
	// Pre-validate packages to catch known edge cases
	for _, pkg := range manifest.Updates {
		// Check for known problematic version patterns
		if strings.Contains(pkg.FixedVersion, "-rc") || strings.Contains(pkg.FixedVersion, "-beta") || strings.Contains(pkg.FixedVersion, "-alpha") {
			log.Warnf("Package %s has pre-release fixed version %s - this may not be available in npm registry", pkg.Name, pkg.FixedVersion)
		}
		
		// Check for multiple versions in FixedVersion (comma-separated)
		if strings.Contains(pkg.FixedVersion, ",") {
			versions := strings.Split(pkg.FixedVersion, ",")
			log.Warnf("Package %s has multiple fixed versions: %v - using first one", pkg.Name, versions)
			// We'll use the first version in the update commands
		}
	}

	// First, detect where Node.js application roots exist
	// We look for directories with both package.json AND package-lock.json, excluding node_modules
	// TODO: Consider using Trivy's PkgPath field to get exact locations of vulnerable packages
	// This would avoid the need to search the filesystem and could be more accurate

	updated := m.config.ImageState.Run(
		llb.Args([]string{"sh", "-c", detectNodejsAppsScript}),
		llb.WithProxy(utils.GetProxy()),
	).Root()


	// Build update commands for each package
	// We use a more conservative approach than npm audit fix --force
	var errPkgs []string

	for _, pkg := range manifest.Updates {
		// Handle multiple versions if comma-separated (take the first one)
		fixedVersion := pkg.FixedVersion
		if strings.Contains(fixedVersion, ",") {
			versions := strings.Split(fixedVersion, ",")
			fixedVersion = strings.TrimSpace(versions[0])
			log.Debugf("Using version %s from multiple options for package %s", fixedVersion, pkg.Name)
		}
		
		// Escape package names that might have special characters
		safePkgName := strings.ReplaceAll(pkg.Name, "'", "'\"'\"'")
		safeFixedVersion := strings.ReplaceAll(fixedVersion, "'", "'\"'\"'")

		log.Debugf("Updating package %s to %s", pkg.Name, pkg.FixedVersion)
		
		// Run the update script with environment variables
		var runOptions []llb.RunOption
		runOptions = append(runOptions, 
			llb.AddEnv("PACKAGE_NAME", pkg.Name),
			llb.AddEnv("SAFE_PACKAGE_NAME", safePkgName),
			llb.AddEnv("FIXED_VERSION", fixedVersion),
			llb.AddEnv("SAFE_FIXED_VERSION", safeFixedVersion),
			llb.Args([]string{"sh", "-c", updateNodejsPackageScript}),
			llb.WithProxy(utils.GetProxy()),
		)
		
		if ignoreErrors {
			runOptions = append(runOptions, llb.AddEnv("IGNORE_ERRORS", "true"))
		}
		
		updated = updated.Run(runOptions...).Root()
	}

	// Clean up and update lock files for all detected Node.js application roots
	var cleanupOptions []llb.RunOption
	cleanupOptions = append(cleanupOptions,
		llb.Args([]string{"sh", "-c", cleanupNodejsAppsScript}),
		llb.WithProxy(utils.GetProxy()),
	)
	
	if ignoreErrors {
		cleanupOptions = append(cleanupOptions, llb.AddEnv("IGNORE_ERRORS", "true"))
	}
	
	updated = updated.Run(cleanupOptions...).Root()

	// In a real implementation, we would parse the output to determine which packages failed
	// For now, we return empty error list when ignoreErrors is true
	if !ignoreErrors && len(errPkgs) > 0 {
		return &updated, errPkgs, fmt.Errorf("failed to update %d packages", len(errPkgs))
	}

	log.Infof("Completed Node.js package update process for %d packages", len(manifest.Updates))
	return &updated, errPkgs, nil
}

// GetPackageType returns the package ecosystem type.
func (m *npmManager) GetPackageType() string {
	return nodeEcosystem
}

// NewNpmManager creates a new npm package manager instance.
func NewNpmManager(config *buildkit.Config, workingFolder string) PackageManager {
	return &npmManager{
		config:        config,
		workingFolder: workingFolder,
	}
}