package patch

import (
	"context"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	configtypes "github.com/docker/cli/cli/config/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	v1types "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/moby/buildkit/solver/pb"
	"github.com/project-copacetic/copacetic/pkg/frontend"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/stretchr/testify/require"
	"github.com/tonistiigi/fsutil"
)

func testAuthenticatedIndexOrigin(t *testing.T, ctx context.Context, bk *client.Client, repo string, application map[string]string) {
	t.Helper()
	t.Run("authenticated-index-origin", func(t *testing.T) {
		for _, mediaType := range []v1types.MediaType{v1types.OCIImageIndex, v1types.DockerManifestList} {
			t.Run(string(mediaType), func(t *testing.T) {
				testAuthenticatedIndexOriginFormat(t, ctx, bk, repo, application, mediaType)
			})
		}
	})
}

func testAuthenticatedIndexOriginFormat(t *testing.T, ctx context.Context, bk *client.Client, repo string, application map[string]string, mediaType v1types.MediaType) {
	t.Helper()
	// These disposable credentials exist only in this fixture's explicit
	// clients/session; Copa's default registry keychain cannot read it.
	const username, password = "copa-origin-test", "ephemeral-registry-test"
	var authenticated atomic.Int64
	registryHandler := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, secret, ok := r.BasicAuth()
		if !ok || user != username || secret != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="copa-origin-test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authenticated.Add(1)
		registryHandler.ServeHTTP(w, r)
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	privateRepo := host + "/private-origin"
	t.Logf("Authenticated origin test registry: %s", privateRepo)
	auth := &authn.Basic{Username: username, Password: password}
	original, err := remote.Index(originTestReference(t, repo+":original"), remote.WithContext(ctx))
	require.NoError(t, err)
	// A fresh index digest prevents BuildKit's content cache from making
	// the credentialless control succeed without contacting this registry.
	privateAnnotations := maps.Clone(application)
	privateAnnotations["com.example.auth-snapshot"] = privateRepo
	original, ok := mutate.Annotations(original, privateAnnotations).(v1.ImageIndex)
	require.True(t, ok)
	original = mutate.IndexMediaType(original, mediaType)
	root, err := original.Digest()
	require.NoError(t, err)
	require.NoError(t, remote.WriteIndex(originTestReference(t, privateRepo+":original"), original, remote.WithAuth(auth), remote.WithContext(ctx)))
	base := privateRepo + "@" + root.String()
	// Retain the real APK patch layer from P1, with the valid index-locator
	// metadata shape used by existing Copa images.
	first, err := remote.Image(originTestReference(t, repo+":p1-amd64"), remote.WithContext(ctx))
	require.NoError(t, err)
	config, err := first.ConfigFile()
	require.NoError(t, err)
	config = config.DeepCopy()
	config.Config.Labels["BaseImage"] = base
	childDigest := config.Config.Labels[types.AnnotationPatchOriginDigest]
	config.Config.Labels[types.AnnotationPatchOriginName] = privateRepo + "@" + childDigest
	first, err = mutate.ConfigFile(first, config)
	require.NoError(t, err)
	annotations := maps.Clone(application)
	maps.Copy(annotations, types.SourceLineageFromAnnotations(config.Config.Labels).Annotations())
	first = originAnnotatedImage(t, first, annotations)
	input := privateRepo + ":p1"
	require.NoError(t, remote.Write(originTestReference(t, input), first, remote.WithAuth(auth), remote.WithContext(ctx)))
	_, err = remote.Get(originTestReference(t, base), remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
	require.Error(t, err, "default client credentials must not resolve this index")
	platform := v1.Platform{OS: "linux", Architecture: originAMD64}
	_, err = bk.Build(ctx, client.SolveOpt{}, "copa-origin-no-auth-control", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		_, err := c.ResolveSourceMetadata(ctx, &pb.SourceOp{Identifier: "docker-image://" + base}, sourceresolver.Opt{ImageOpt: &sourceresolver.ResolveImageOpt{
			ResolveMode: llb.ResolveModePreferLocal.String(),
		}})
		return nil, err
	}, nil)
	require.Error(t, err, "a BuildKit session without credentials must also fail")
	provider := authprovider.NewDockerAuthProvider(authprovider.DockerAuthProviderConfig{
		AuthConfigProvider: func(_ context.Context, registryHost string, _ []string, _ authprovider.ExpireCachedAuthCheck) (configtypes.AuthConfig, error) {
			if registryHost == host {
				return configtypes.AuthConfig{Username: username, Password: password}, nil
			}
			return configtypes.AuthConfig{}, nil
		},
	})
	report := originTestReport(t, originAMD64)
	mount, err := fsutil.NewFS(filepath.Dir(report))
	require.NoError(t, err)
	output := privateRepo + ":p2"
	before := authenticated.Load()
	_, err = bk.Build(ctx, client.SolveOpt{
		Session:       []session.Attachable{provider},
		FrontendAttrs: map[string]string{"image": input, "platform": "linux/amd64", "report": filepath.Base(report)},
		LocalMounts:   map[string]fsutil.FS{"report": mount},
		Exports: []client.ExportEntry{{Type: client.ExporterImage, Attrs: map[string]string{
			"name": output, "push": "true", "registry.insecure": "true", "oci-mediatypes": "true",
		}}},
	}, "copa-origin-auth-session", frontend.Build, nil)
	require.NoError(t, err)
	require.Greater(t, authenticated.Load(), before, "the actual build must authenticate")
	image, err := remote.Image(originTestReference(t, output), remote.WithAuth(auth), remote.WithContext(ctx), remote.WithPlatform(platform))
	require.NoError(t, err)
	manifest, err := image.Manifest()
	require.NoError(t, err)
	outputConfig, err := image.ConfigFile()
	require.NoError(t, err)
	for _, surface := range []map[string]string{manifest.Annotations, outputConfig.Config.Labels} {
		require.Equal(t, types.PatchOriginImage, surface[types.AnnotationPatchOriginKind])
		require.Equal(t, privateRepo+"@"+childDigest, surface[types.AnnotationPatchOriginName])
		require.Equal(t, childDigest, surface[types.AnnotationPatchOriginDigest])
	}
	// The frontend's application-metadata contract preserves config labels;
	// it does not copy arbitrary input manifest annotations into new outputs.
	for key, value := range application {
		require.Equal(t, value, outputConfig.Config.Labels[key])
	}
	require.Equal(t, base, outputConfig.Config.Labels["BaseImage"])
	verifyOriginBlobs(t, image)
}
