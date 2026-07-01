package patch

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/docker/cli/cli/config"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	sourcepolicy "github.com/moby/buildkit/sourcepolicy/pb"
)

const (
	attrValueTrue                 = "true"
	defaultLocalExportCompression = "uncompressed"
)

// BuildConfig holds configuration for building and exporting images.
type BuildConfig struct {
	SolveOpt        client.SolveOpt
	ShouldExportOCI bool
	PipeWriter      io.WriteCloser
}

// createBuildConfig creates the build configuration for patching.
// originalAnnotations is the set of manifest-level annotations captured from the
// source image before patching; they are forwarded to the BuildKit exporter via
// `annotation.<key>` attrs so that single-platform pushes (and Docker-format
// loads) preserve metadata such as org.opencontainers.image.{source,revision,
// version,title}. Without this, the exporter would write a manifest carrying
// only Copa's own annotations and silently drop everything else. patchedTag is
// the final tag of the patched image, used to rewrite
// org.opencontainers.image.version so the patched manifest does not advertise
// the unpatched version (matches the index-level rewrite in
// pkg/patch/manifest.go).
//
// Note: BuildKit's Docker exporter (--load and Docker schema 2 push) writes a
// manifest format that has no `annotations` field; the annotation.* attrs are
// silently dropped there. Annotations are preserved end-to-end only on OCI
// exports. This matches the pre-existing behavior of the
// sh.copa.image.patched annotation.
func createBuildConfig(
	patchedImageName string,
	shouldExportOCI bool,
	push bool,
	pipeW io.WriteCloser,
	originalAnnotations map[string]string,
	patchedTag string,
	compression string,
	forceCompression bool,
) (*BuildConfig, error) {
	dockerConfig := config.LoadDefaultConfigFile(os.Stderr)
	cfg := authprovider.DockerAuthProviderConfig{AuthConfigProvider: authprovider.LoadAuthConfig(dockerConfig)}
	attachable := []session.Attachable{authprovider.NewDockerAuthProvider(cfg)}

	// create solve options based on whether we're pushing to registry or loading to docker
	solveOpt := client.SolveOpt{
		Frontend: "",         // i.e. we are passing in the llb.Definition directly
		Session:  attachable, // used for authprovider, sshagentprovider and secretprovider
	}

	// determine which attributes to set for the export
	attrs := map[string]string{
		"name": patchedImageName,
	}
	// Forward original manifest annotations into the exporter so the pushed/
	// loaded manifest preserves them. Copa's own annotations below always win
	// when their keys collide because we set them last.
	for k, v := range originalAnnotations {
		attrs["annotation."+k] = v
	}
	// Copa-specific annotations: bump the OCI created time and stamp our patched marker.
	now := time.Now().UTC().Format(time.RFC3339)
	attrs["annotation.org.opencontainers.image.created"] = now
	attrs["annotation."+copaAnnotationKeyPrefix+".image.patched"] = now
	// Rewrite org.opencontainers.image.version to reflect the patched tag so the
	// patched manifest does not advertise the unpatched version. Mirrors the
	// index-level rewrite in createMultiPlatformManifest.
	if origVersion, ok := originalAnnotations["org.opencontainers.image.version"]; ok && patchedTag != "" {
		attrs["annotation.org.opencontainers.image.version"] = rewriteVersionAnnotation(origVersion, patchedTag)
	}
	if shouldExportOCI {
		attrs["oci-mediatypes"] = attrValueTrue
	}

	if push {
		attrs["push"] = attrValueTrue
		solveOpt.Exports = []client.ExportEntry{
			{
				Type:  client.ExporterImage,
				Attrs: attrs,
			},
		}
	} else {
		// Use uncompressed layers for local export to ensure diff_id == blob digest
		// for newly created patch layers. This fixes Trivy scanning issues where
		// compressed layers have mismatched hashes without forcing BuildKit to
		// re-encode existing base layers unless explicitly requested.
		if compression == "" {
			compression = defaultLocalExportCompression
		}
		attrs["compression"] = compression
		if forceCompression {
			attrs["force-compression"] = attrValueTrue
		}

		solveOpt.Exports = []client.ExportEntry{
			{
				Type:  client.ExporterDocker,
				Attrs: attrs,
				Output: func(_ map[string]string) (io.WriteCloser, error) {
					return pipeW, nil
				},
			},
		}
	}

	// Set source policy
	sourcePolicy, err := readSourcePolicy()
	if err != nil {
		return nil, err
	}
	solveOpt.SourcePolicy = sourcePolicy

	if err := validateSourcePolicy(solveOpt.SourcePolicy); err != nil {
		return nil, err
	}

	return &BuildConfig{
		SolveOpt:        solveOpt,
		ShouldExportOCI: shouldExportOCI,
		PipeWriter:      pipeW,
	}, nil
}

// rewriteVersionAnnotation returns the value to write for
// org.opencontainers.image.version on a patched image. If the patched tag
// already contains the original version (e.g. "1.0.0" patched to
// "1.0.0-patched"), the full patched tag is used as the new version. Otherwise
// the patched tag is appended as a suffix (e.g. "1.0.0" + "patched"
// -> "1.0.0-patched") so the patched manifest does not advertise the
// unpatched version.
func rewriteVersionAnnotation(originalVersion, patchedTag string) string {
	if patchedTag == "" {
		return originalVersion
	}
	if strings.Contains(patchedTag, originalVersion) {
		return patchedTag
	}
	return originalVersion + "-" + patchedTag
}

// validateSourcePolicy validates that the source policy doesn't contain unsupported distributions.
func validateSourcePolicy(sourcePolicy *sourcepolicy.Policy) error {
	if sourcePolicy == nil || len(sourcePolicy.Rules) == 0 {
		return nil
	}

	rule := sourcePolicy.Rules[0]
	identifier := rule.Updates.Identifier

	switch {
	case strings.Contains(identifier, "redhat"):
		return errors.New("RedHat is not supported via source policies due to BusyBox not being in the RHEL repos\n" +
			"Please use a different RPM-based image")

	case strings.Contains(identifier, "rockylinux"):
		return errors.New("RockyLinux is not supported via source policies due to BusyBox not being in the RockyLinux repos\n" +
			"Please use a different RPM-based image")

	case strings.Contains(identifier, "alma"):
		return errors.New("AlmaLinux is not supported via source policies due to BusyBox not being in the AlmaLinux repos\n" +
			"Please use a different RPM-based image")
	}

	return nil
}

// readSourcePolicy reads a BuildKit source policy from the file specified by
// EXPERIMENTAL_BUILDKIT_SOURCE_POLICY. Inlined from docker/buildx/build to
// avoid pulling in docker/docker as a transitive dependency.
func readSourcePolicy() (*sourcepolicy.Policy, error) {
	p := os.Getenv("EXPERIMENTAL_BUILDKIT_SOURCE_POLICY")
	if p == "" {
		return nil, nil
	}

	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("failed to read source policy file: %w", err)
	}
	var pol sourcepolicy.Policy
	if err := json.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("failed to parse source policy: %w", err)
	}
	return &pol, nil
}
