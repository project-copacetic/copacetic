package frontend

import (
	"context"
	"strings"

	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/pkg/errors"
)

// LLBGraphBuilder constructs LLB graphs with advanced features
type LLBGraphBuilder struct {
	client gwclient.Client
	config *FrontendConfig
}

// NewLLBGraphBuilder creates a new LLB graph builder
func NewLLBGraphBuilder(client gwclient.Client, config *FrontendConfig) *LLBGraphBuilder {
	return &LLBGraphBuilder{
		client: client,
		config: config,
	}
}

// BuildPatchedImage constructs an LLB graph for patching an image
func (b *LLBGraphBuilder) BuildPatchedImage(ctx context.Context, baseState llb.State, patchCommands []string) (llb.State, error) {
	// Apply security constraints if specified
	if b.config.SecurityMode == "sandbox" {
		baseState = b.applySecurityConstraints(baseState)
	}

	// Stage 1: Probe - Analyze current package state (for future use)
	_ = b.buildProbeOperation(baseState)

	// Stage 2: Tooling - Deploy patching tools if needed (minimal approach)
	toolingState := b.buildToolingOperation(baseState)

	// Stage 3: Patching - Apply security updates
	patchState := b.buildPatchOperation(toolingState, patchCommands)

	// Use DiffOp to create minimal patch layer (following Claude's plan)
	patchLayer := llb.Diff(baseState, patchState, llb.WithCustomName("[copa] creating patch layer"))

	// Merge to create final image with minimal layers
	finalState := llb.Merge([]llb.State{baseState, patchLayer}, llb.WithCustomName("[copa] merging patch layer"))

	// Apply caching if configured
	if b.config.CacheMode != "" {
		finalState = b.applyCaching(finalState)
	}

	return finalState, nil
}

// buildProbeOperation creates an LLB operation to probe package state
func (b *LLBGraphBuilder) buildProbeOperation(base llb.State) llb.State {
	// Detect package manager and list installed packages
	probeCmd := b.getProbeCommand()
	
	return base.Run(
		llb.Shlex(probeCmd),
		llb.WithCustomName("[copa] probing package state"),
	).Root()
}

// getProbeCommand returns the appropriate command to probe package state
func (b *LLBGraphBuilder) getProbeCommand() string {
	if b.config.PkgMgr != "" {
		switch b.config.PkgMgr {
		case "apt":
			return "dpkg -l > /tmp/packages.list || true"
		case "apk":
			return "apk list -I > /tmp/packages.list || true"
		case "yum", "dnf":
			return "rpm -qa > /tmp/packages.list || true"
		}
	}

	// Auto-detect package manager
	return "sh -c 'dpkg -l > /tmp/packages.list 2>/dev/null || rpm -qa > /tmp/packages.list 2>/dev/null || apk list -I > /tmp/packages.list 2>/dev/null || true'"
}

// buildToolingOperation deploys minimal patching tools if needed
func (b *LLBGraphBuilder) buildToolingOperation(base llb.State) llb.State {
	// For most cases, the base image already has the package manager
	// This is a placeholder for cases where we need to install tools
	
	if b.config.OfflineMode {
		// In offline mode, assume all tools are already present
		return base
	}

	// Add minimal tooling if needed (placeholder for future enhancement)
	return base.Run(
		llb.Shlex("echo 'tooling check complete'"),
		llb.WithCustomName("[copa] tooling verification"),
	).Root()
}

// buildPatchOperation applies security patches
func (b *LLBGraphBuilder) buildPatchOperation(base llb.State, patchCommands []string) llb.State {
	if len(patchCommands) == 0 {
		return base
	}

	// Combine all patch commands into a single operation for efficiency
	combinedCmd := strings.Join(patchCommands, " && ")
	
	// Add package mirror configuration for air-gapped environments if needed
	runOpts := []llb.RunOption{
		llb.Shlex(combinedCmd),
		llb.WithCustomName("[copa] applying security patches"),
	}
	
	if b.config.PackageMirror != "" {
		runOpts = append(runOpts, llb.AddEnv("PACKAGE_MIRROR", b.config.PackageMirror))
	}

	return base.Run(runOpts...).Root()
}

// applySecurityConstraints adds security constraints to LLB operations
func (b *LLBGraphBuilder) applySecurityConstraints(state llb.State) llb.State {
	switch b.config.SecurityMode {
	case "sandbox":
		return state.
			Security(llb.SecurityModeSandbox).
			Network(llb.NetModeNone)
	case "insecure":
		return state.Security(llb.SecurityModeInsecure)
	default:
		// Default to sandbox mode for security
		return state.Security(llb.SecurityModeSandbox)
	}
}

// applyCaching applies caching strategies to LLB operations
func (b *LLBGraphBuilder) applyCaching(state llb.State) llb.State {
	switch b.config.CacheMode {
	case "local":
		// Enable local caching (BuildKit handles this automatically)
		return state
	case "registry":
		// Registry caching would be configured at BuildKit level
		return state
	case "disabled":
		// Disable caching by adding unique operations
		return state.Dir("/tmp").Run(
			llb.Shlex("echo 'cache-disabled' > /tmp/cache-bust"),
		).Root()
	default:
		return state
	}
}

// BuildScanOperation creates an LLB operation for vulnerability scanning (future enhancement)
func (b *LLBGraphBuilder) BuildScanOperation(ctx context.Context, base llb.State, scanner Scanner) (llb.State, error) {
	// This is a placeholder for future live scanning capabilities
	// For now, Copa frontend expects pre-generated vulnerability reports
	
	if !scanner.CanScanImage("") {
		return llb.State{}, errors.New("scanner cannot scan this image type")
	}

	// Future implementation would create an LLB operation to run the scanner
	return llb.State{}, errors.New("live scanning not yet implemented - use pre-generated reports")
}