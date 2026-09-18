package patch

import (
	"context"
	"fmt"

	"github.com/distribution/reference"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/opencontainers/go-digest"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

type platformPatchInput struct {
	image       string
	digest      digest.Digest
	annotations map[string]string
	updates     *unversioned.UpdateManifest
	reportErr   error
}

func (input platformPatchInput) needsPatch() bool {
	return input.reportErr == nil && (input.updates == nil || len(input.updates.OSUpdates) > 0 || len(input.updates.LangUpdates) > 0)
}

// All selected patching children must recover and validate their complete origin
// before any child can export. Package-manager ignore-errors does not apply to
// these source integrity checks. Preserved and empty-report children do not
// introduce a new BuildKit requirement.
func preflightMultiPlatformOrigins(ctx context.Context, opts *types.Options, platforms []types.PatchPlatform, inputs map[string]platformPatchInput, root digest.Digest) error {
	var selected []types.PatchPlatform
	for _, p := range platforms {
		if input, ok := inputs[buildkit.PlatformKey(p.Platform)]; ok && input.needsPatch() {
			selected = append(selected, p)
		}
	}
	if len(selected) == 0 {
		return nil
	}
	bk, err := bkNewClient(ctx, buildkit.Opts{Addr: opts.BkAddr, CACertPath: opts.BkCACertPath, CertPath: opts.BkCertPath, KeyPath: opts.BkKeyPath})
	if err != nil {
		return fmt.Errorf("preflight platform origins: %w", err)
	}
	defer bk.Close()
	source, err := reference.ParseNormalizedNamed(opts.Image)
	if err != nil {
		return err
	}
	solveOpt := authenticatedSolveOpt()
	solveOpt.SourcePolicy, err = readSourcePolicy()
	if err != nil {
		return err
	}
	if err := validateSourcePolicy(solveOpt.SourcePolicy); err != nil {
		return err
	}
	_, err = bk.Build(ctx, solveOpt, copaProduct, func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		for _, p := range selected {
			key := buildkit.PlatformKey(p.Platform)
			input := inputs[key]
			if _, local, err := localPlatformDescriptor(ctx, opts.Image, &p.Platform); local {
				if err != nil {
					return nil, err
				}
				if err := primeLocalSourceWithClient(ctx, c, opts.Image, root, input.digest, &p.Platform); err != nil {
					return nil, fmt.Errorf("prepare captured local source for platform %s: %w", key, err)
				}
			}
			_, err := initializePatchConfig(ctx, c, &Options{
				ImageName: input.image, TargetPlatform: &p, SourceImageName: resolveImageReference(source),
				ExpectedSourceDigest: input.digest, RequireBaseManifest: true,
			}, input.annotations)
			if err != nil {
				return nil, fmt.Errorf("validate origin for platform %s: %w", key, err)
			}
		}
		return gwclient.NewResult(), nil
	}, nil)
	return err
}
