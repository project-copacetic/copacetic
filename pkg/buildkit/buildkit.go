package buildkit

import (
	"bytes"
	"context"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types/unversioned"
)

type Config struct {
	ImageName  string
	Client     gwclient.Client
	ConfigData []byte
	Platform   ispec.Platform
	ImageState llb.State
}

type Opts struct {
	Addr       string
	CACertPath string
	CertPath   string
	KeyPath    string
}

func InitializeBuildkitConfig(ctx context.Context, c gwclient.Client, image string, manifest *unversioned.UpdateManifest) (*Config, error) {
	// Initialize buildkit config for the target image
	config := Config{
		ImageName: image,
		Platform: ispec.Platform{
			OS:           "linux",
			Architecture: manifest.Metadata.Config.Arch,
		},
	}

	// Resolve and pull the config for the target image
	_, _, configData, err := c.ResolveImageConfig(ctx, image, sourceresolver.Opt{
		ImageOpt: &sourceresolver.ResolveImageOpt{
			ResolveMode: llb.ResolveModePreferLocal.String(),
		},
	})
	if err != nil {
		return nil, err
	}

	config.ConfigData = configData

	// Load the target image state with the resolved image config in case environment variable settings
	// are necessary for running apps in the target image for updates
	config.ImageState, err = llb.Image(image,
		llb.Platform(config.Platform),
		llb.ResolveModePreferLocal,
		llb.WithMetaResolver(c),
	).WithImageConfig(config.ConfigData)
	if err != nil {
		return nil, err
	}

	config.Client = c

	return &config, nil
}

// Extracts the bytes of the file denoted by `path` from the state `st`.
func ExtractFileFromState(ctx context.Context, c gwclient.Client, st *llb.State, path string) ([]byte, error) {
	def, err := st.Marshal(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := c.Solve(ctx, gwclient.SolveRequest{
		Evaluate:   true,
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, err
	}

	ref, err := resp.SingleRef()
	if err != nil {
		return nil, err
	}

	return ref.ReadFile(ctx, gwclient.ReadRequest{
		Filename: path,
	})
}

func ArrayFile(input []string) []byte {
	var b bytes.Buffer
	for _, s := range input {
		b.WriteString(s)
		b.WriteRune('\n') // newline
	}
	return b.Bytes()
}

func WithArrayFile(s *llb.State, path string, contents []string) llb.State {
	af := ArrayFile(contents)
	return WithFileBytes(s, path, af)
}

func WithFileString(s *llb.State, path, contents string) llb.State {
	return WithFileBytes(s, path, []byte(contents))
}

func WithFileBytes(s *llb.State, path string, contents []byte) llb.State {
	return s.File(llb.Mkfile(path, 0o600, contents))
}
