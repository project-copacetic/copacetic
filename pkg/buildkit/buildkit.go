package buildkit

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/containerd/containerd/platforms"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Config struct {
	ImageName  string
	Client     gwclient.Client
	ConfigData []byte
	Platform   *ispec.Platform
	ImageState llb.State
}

type Opts struct {
	Addr       string
	CACertPath string
	CertPath   string
	KeyPath    string
}

func InitializeBuildkitConfig(ctx context.Context, c gwclient.Client, image string) (*Config, error) {
	// Initialize buildkit config for the target image
	config := Config{
		ImageName: image,
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

	// Unmarshal ConfigData so we can work with the data structure
	// The unmarshalled format is stored in userImageMetadata
	var userImageMetadata map[string]interface{}
	unmarshalErr := json.Unmarshal(config.ConfigData, &userImageMetadata)
	if unmarshalErr != nil {
		return nil, unmarshalErr
	}

	// configMap is set specifically to the data stored within the "config" directive
	configMap := userImageMetadata["config"].(map[string]interface{})
	if labels, ok := configMap["labels"]; ok {
		// If labels already exists, add BaseImage metadata
		labels.(map[string]string)["BaseImage"] = image
	} else {
		// If labels do not exist, create labels and add BaseImage metadata
		labels = make(map[string]string)
		configMap["Labels"] = labels
		labels.(map[string]string)["BaseImage"] = image
	}

	// We need to marshal the data back into a byte array and assign the modified user image metadata into config.ConfigData
	configMapBytes, err := json.Marshal(userImageMetadata)
	config.ConfigData = configMapBytes

	// Load the target image state with the resolved image config in case environment variable settings
	// are necessary for running apps in the target image for updates
	config.ImageState, err = llb.Image(image,
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
	// since platform is obtained from host, override it in the case of Darwin
	platform := platforms.Normalize(platforms.DefaultSpec())
	if platform.OS != "linux" {
		platform.OS = "linux"
	}

	def, err := st.Marshal(ctx, llb.Platform(platform))
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
