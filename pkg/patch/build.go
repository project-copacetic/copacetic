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
	"google.golang.org/protobuf/proto"
)

const (
	attrValueTrue = "true"
)

// BuildConfig holds configuration for building and exporting images.
type BuildConfig struct {
	SolveOpt        client.SolveOpt
	ShouldExportOCI bool
	PipeWriter      io.WriteCloser
}

// createBuildConfig creates the build configuration for patching.
func createBuildConfig(
	patchedImageName string,
	shouldExportOCI bool,
	push bool,
	pipeW io.WriteCloser,
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
		"annotation." + copaAnnotationKeyPrefix + ".image.patched": time.Now().UTC().Format(time.RFC3339),
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
		// This fixes Trivy scanning issues where compressed layers have mismatched hashes
		attrs["compression"] = "uncompressed"
		attrs["force-compression"] = attrValueTrue

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
			return nil, fmt.Errorf("failed to parse source policy: %w", e2)
			return nil, fmt.Errorf("failed to parse source policy: %w", err)
		}
	}
	return &pol, nil
}
