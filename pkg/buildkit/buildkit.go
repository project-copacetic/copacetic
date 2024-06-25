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
	ImageName         string
	Client            gwclient.Client
	ConfigData        []byte
	PatchedConfigData []byte
	Platform          *ispec.Platform
	ImageState        llb.State
	PatchedImageState llb.State
}

type Opts struct {
	Addr       string
	CACertPath string
	CertPath   string
	KeyPath    string
}

func InitializeBuildkitConfig(ctx context.Context, c gwclient.Client, userImage string) (*Config, error) {
	// Initialize buildkit config for the target image
	config := Config{
		ImageName: userImage,
	}

	// Resolve and pull the config for the target image
	_, _, configData, err := c.ResolveImageConfig(ctx, userImage, sourceresolver.Opt{
		ImageOpt: &sourceresolver.ResolveImageOpt{
			ResolveMode: llb.ResolveModePreferLocal.String(),
		},
	})
	if err != nil {
		return nil, err
	}

	var baseImage string
	config.ConfigData, config.PatchedConfigData, baseImage, err = updateImageMetadata(ctx, c, configData, userImage)
	if err != nil {
		return nil, err
	}

	// Load the target image state with the resolved image config in case environment variable settings
	// are necessary for running apps in the target image for updates
	config.ImageState, err = llb.Image(baseImage,
		llb.ResolveModePreferLocal,
		llb.WithMetaResolver(c),
	).WithImageConfig(config.ConfigData)
	if err != nil {
		return nil, err
	}

	// Only set PatchedConfigData if the user supplied a patched image
	// image in this case should always refer to the patched image (if it exists)
	if config.PatchedConfigData != nil {
		config.PatchedImageState, err = llb.Image(userImage,
			llb.ResolveModePreferLocal,
			llb.WithMetaResolver(c),
		).WithImageConfig(config.PatchedConfigData)
		if err != nil {
			return nil, err
		}
	}

	config.Client = c

	return &config, nil
}

func updateImageMetadata(ctx context.Context, c gwclient.Client, configData []byte, image string) ([]byte, []byte, string, error) {
	var patchedImageMetadata []byte
	baseImage, userImageMetadata := setupLabels(configData, image)

	if baseImage == "" {
		configData = userImageMetadata
	} else {
		patchedImageMetadata = userImageMetadata
		_, _, baseImageMetadata, err := c.ResolveImageConfig(ctx, baseImage, sourceresolver.Opt{
			ImageOpt: &sourceresolver.ResolveImageOpt{
				ResolveMode: llb.ResolveModePreferLocal.String(),
			},
		})
		if err != nil {
			return nil, nil, "", err
		}
		// Pass this into setupLabels so that labels can properly be applied to an already patched image
		_, baseImageWithLabels := setupLabels(baseImageMetadata, baseImage)
		configData = baseImageWithLabels

		return configData, patchedImageMetadata, baseImage, nil
	}

	return configData, nil, baseImage, nil
}

// Sets up labels for the image based on the provided configuration data and image name.
// If the labels are already present in the configuration data, it returns the value of the "BaseImage" label.
// Otherwise, it adds the "BaseImage" label with the provided image name and returns the updated configuration data.
// The updated configuration data is returned as a JSON byte slice.
func setupLabels(configData []byte, image string) (string, []byte) {
	imageMetadata := make(map[string]interface{})
	err := json.Unmarshal(configData, &imageMetadata)
	if err != nil {
		return "", nil
	}

	configMap := imageMetadata["config"].(map[string]interface{})

	var baseImage string
	labels := configMap["labels"]
	if labels == nil {
		labels = make(map[string]interface{})
		configMap["labels"] = labels
	}
	labelsMap := labels.(map[string]interface{})
	if _, ok := labelsMap["BaseImage"]; ok {
		baseImage = labelsMap["BaseImage"].(string)
	} else {
		labelsMap["BaseImage"] = image
	}

	imageWithLabels, _ := json.Marshal(imageMetadata)

	return baseImage, imageWithLabels
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
