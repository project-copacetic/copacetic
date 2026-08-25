package buildkit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	remotev1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	remoteTypes "github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/client/llb"
	exptypes "github.com/moby/buildkit/exporter/containerimage/exptypes"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	fstypes "github.com/tonistiigi/fsutil/types"

	"github.com/project-copacetic/copacetic/mocks"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"

	"github.com/stretchr/testify/mock"

	controlapi "github.com/moby/buildkit/api/services/control"
	bk_types "github.com/moby/buildkit/api/types"
	gateway "github.com/moby/buildkit/frontend/gateway/pb"
	"github.com/moby/buildkit/util/apicaps"
	caps "github.com/moby/buildkit/util/apicaps/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func testRemoteIndexDescriptor(digestHex string) *remote.Descriptor {
	raw := []byte(`{
		"schemaVersion":2,
		"mediaType":"application/vnd.oci.image.index.v1+json",
		"manifests":[
			{
				"mediaType":"application/vnd.oci.image.manifest.v1+json",
				"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"size":1,
				"platform":{"os":"linux","architecture":"amd64"}
			},
			{
				"mediaType":"application/vnd.oci.image.manifest.v1+json",
				"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				"size":1,
				"platform":{"os":"linux","architecture":"arm64"}
			}
		]
	}`)
	return &remote.Descriptor{
		Descriptor: remotev1.Descriptor{
			MediaType: remoteTypes.OCIImageIndex,
			Size:      int64(len(raw)),
			Digest:    remotev1.Hash{Algorithm: "sha256", Hex: digestHex},
		},
		Manifest: raw,
	}
}

func TestGetVerifiedRemoteIndex(t *testing.T) {
	const requestedDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	ref, err := name.NewDigest("example.com/test/image@sha256:" + requestedDigest)
	require.NoError(t, err)

	originalRemote := getRemoteImageDescriptor
	t.Cleanup(func() { getRemoteImageDescriptor = originalRemote })

	tests := []struct {
		name     string
		desc     *remote.Descriptor
		fetchErr error
		wantErr  string
	}{
		{
			name: "matching immutable index",
			desc: testRemoteIndexDescriptor(requestedDigest),
		},
		{
			name:    "mismatched index digest",
			desc:    testRemoteIndexDescriptor("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
			wantErr: "does not match immutable reference",
		},
		{
			name: "single image manifest",
			desc: &remote.Descriptor{Descriptor: remotev1.Descriptor{
				MediaType: remoteTypes.OCIManifestSchema1,
				Digest:    remotev1.Hash{Algorithm: "sha256", Hex: requestedDigest},
			}},
			wantErr: "is not an image index",
		},
		{
			name:    "empty registry response",
			wantErr: "returned no descriptor",
		},
		{
			name:     "registry error",
			fetchErr: errors.New("registry unavailable"),
			wantErr:  "registry unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getRemoteImageDescriptor = func(gotRef name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
				assert.Equal(t, ref.String(), gotRef.String())
				return tt.desc, tt.fetchErr
			}

			got, err := GetVerifiedRemoteIndex(ref)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Same(t, tt.desc, got)
		})
	}
}

func TestTryGetManifestFromLocalUsesDockerIndexMetadata(t *testing.T) {
	const imageRef = "registry.example.com/local:latest"
	indexDigest := digest.Digest("sha256:" + strings.Repeat("c", 64))
	originalLocalIndex := localImageIndex
	t.Cleanup(func() { localImageIndex = originalLocalIndex })

	localImageIndex = func(context.Context, string) (*ispec.Index, *ispec.Descriptor, bool, bool, error) {
		return &ispec.Index{
			MediaType: ispec.MediaTypeImageIndex,
			Manifests: []ispec.Descriptor{
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    digest.Digest("sha256:" + strings.Repeat("a", 64)),
					Platform:  &ispec.Platform{OS: "linux", Architecture: "amd64"},
				},
				{
					MediaType: ispec.MediaTypeImageManifest,
					Digest:    digest.Digest("sha256:" + strings.Repeat("b", 64)),
					Platform:  &ispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"},
				},
			},
		}, &ispec.Descriptor{MediaType: ispec.MediaTypeImageIndex, Digest: indexDigest}, true, true, nil
	}

	ref, err := name.ParseReference(imageRef)
	require.NoError(t, err)
	desc, sourceDigest, complete, err := getManifestFromLocal(ref)
	require.NoError(t, err)
	assert.True(t, complete)
	assert.True(t, desc.MediaType.IsIndex())
	manifestSum := sha256.Sum256(desc.Manifest)
	assert.Equal(t, fmt.Sprintf("sha256:%x", manifestSum), desc.Digest.String())
	assert.Equal(t, indexDigest.String(), sourceDigest.String())

	var index ispec.Index
	require.NoError(t, json.Unmarshal(desc.Manifest, &index))
	require.Len(t, index.Manifests, 2)
	assert.Equal(t, "amd64", index.Manifests[0].Platform.Architecture)
	assert.Equal(t, "arm64", index.Manifests[1].Platform.Architecture)
}

func TestResolvePreservedPlatformsDescriptorKeepsLocalIndexAuthoritative(t *testing.T) {
	const requestedDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	ref, err := name.NewDigest("example.com/test/image@sha256:" + requestedDigest)
	require.NoError(t, err)
	localIndex := testRemoteIndexDescriptor(requestedDigest)
	manifestSum := sha256.Sum256(localIndex.Manifest)
	localIndex.Digest = remotev1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", manifestSum)}
	sourceDigest := remotev1.Hash{Algorithm: "sha256", Hex: requestedDigest}

	originalLocal := tryGetManifestFromLocal
	originalRemote := getRemoteImageDescriptor
	t.Cleanup(func() {
		tryGetManifestFromLocal = originalLocal
		getRemoteImageDescriptor = originalRemote
	})
	tryGetManifestFromLocal = func(name.Reference) (*remote.Descriptor, remotev1.Hash, bool, error) {
		return localIndex, sourceDigest, true, nil
	}
	getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
		t.Fatal("remote registry must not be consulted for a locally inspected index")
		return nil, nil
	}

	got, isLocal, err := resolvePreservedPlatformsDescriptor(ref)
	require.NoError(t, err)
	assert.True(t, isLocal)
	assert.Same(t, localIndex, got)

	tryGetManifestFromLocal = func(name.Reference) (*remote.Descriptor, remotev1.Hash, bool, error) {
		return localIndex, remotev1.Hash{Algorithm: "sha256", Hex: strings.Repeat("d", 64)}, true, nil
	}
	_, _, err = resolvePreservedPlatformsDescriptor(ref)
	require.ErrorContains(t, err, "does not match immutable reference")
}

func TestResolvePreservedPlatformsDescriptorReconcilesIncompleteLocalIndex(t *testing.T) {
	const sourceHex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	sourceDigest := remotev1.Hash{Algorithm: "sha256", Hex: sourceHex}
	localIndex := testRemoteIndexDescriptor(sourceHex)
	manifestSum := sha256.Sum256(localIndex.Manifest)
	localIndex.Digest = remotev1.Hash{Algorithm: "sha256", Hex: fmt.Sprintf("%x", manifestSum)}
	remoteIndex := testRemoteIndexDescriptor(sourceHex)

	immutableRef, err := name.NewDigest("example.com/test/image@" + sourceDigest.String())
	require.NoError(t, err)
	mutableRef, err := name.ParseReference("example.com/test/image:latest")
	require.NoError(t, err)

	originalLocal := tryGetManifestFromLocal
	originalRemote := getRemoteImageDescriptor
	t.Cleanup(func() {
		tryGetManifestFromLocal = originalLocal
		getRemoteImageDescriptor = originalRemote
	})

	for _, ref := range []name.Reference{immutableRef, mutableRef} {
		t.Run(ref.Identifier(), func(t *testing.T) {
			tryGetManifestFromLocal = func(gotRef name.Reference) (*remote.Descriptor, remotev1.Hash, bool, error) {
				assert.Equal(t, ref.String(), gotRef.String())
				return localIndex, sourceDigest, false, nil
			}
			getRemoteImageDescriptor = func(gotRef name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
				assert.Equal(t, ref.Context().Digest(sourceDigest.String()).String(), gotRef.String())
				return remoteIndex, nil
			}

			got, isLocal, err := resolvePreservedPlatformsDescriptor(ref)
			require.NoError(t, err)
			assert.False(t, isLocal)
			assert.Same(t, remoteIndex, got)
		})
	}
}

func TestResolvePreservedPlatformsDescriptorReconcilesImmutableIndex(t *testing.T) {
	const requestedDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	immutableRef, err := name.NewDigest("example.com/test/image@sha256:" + requestedDigest)
	require.NoError(t, err)
	mutableRef, err := name.ParseReference("example.com/test/image:latest")
	require.NoError(t, err)

	localChild := &remote.Descriptor{Descriptor: remotev1.Descriptor{
		MediaType: remoteTypes.OCIManifestSchema1,
		Digest:    remotev1.Hash{Algorithm: "sha256", Hex: requestedDigest},
	}}

	originalLocal := tryGetManifestFromLocal
	originalRemote := getRemoteImageDescriptor
	t.Cleanup(func() {
		tryGetManifestFromLocal = originalLocal
		getRemoteImageDescriptor = originalRemote
	})

	remoteFailure := errors.New("registry unavailable")
	tests := []struct {
		name              string
		ref               name.Reference
		remoteDesc        *remote.Descriptor
		remoteErr         error
		wantRemoteCall    bool
		wantLocal         bool
		wantDescriptor    *remote.Descriptor
		wantManifestCount int
		wantErr           string
	}{
		{
			name:              "matching remote index replaces locally cached child",
			ref:               immutableRef,
			remoteDesc:        testRemoteIndexDescriptor(requestedDigest),
			wantRemoteCall:    true,
			wantLocal:         false,
			wantManifestCount: 2,
		},
		{
			name:           "matching remote single manifest keeps local child",
			ref:            immutableRef,
			remoteDesc:     localChild,
			wantRemoteCall: true,
			wantLocal:      true,
			wantDescriptor: localChild,
		},
		{
			name:           "mismatched remote digest fails closed",
			ref:            immutableRef,
			remoteDesc:     testRemoteIndexDescriptor("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
			wantRemoteCall: true,
			wantErr:        "does not match immutable reference",
		},
		{
			name:           "remote verification failure fails closed",
			ref:            immutableRef,
			remoteErr:      remoteFailure,
			wantRemoteCall: true,
			wantErr:        "verify immutable descriptor",
		},
		{
			name:           "mutable tag keeps locally cached child",
			ref:            mutableRef,
			wantLocal:      true,
			wantDescriptor: localChild,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remoteCalls := 0
			tryGetManifestFromLocal = func(gotRef name.Reference) (*remote.Descriptor, remotev1.Hash, bool, error) {
				assert.Equal(t, tt.ref.String(), gotRef.String())
				return localChild, localChild.Digest, true, nil
			}
			getRemoteImageDescriptor = func(gotRef name.Reference, _ ...remote.Option) (*remote.Descriptor, error) {
				remoteCalls++
				assert.Equal(t, tt.ref.String(), gotRef.String())
				return tt.remoteDesc, tt.remoteErr
			}

			got, isLocal, err := resolvePreservedPlatformsDescriptor(tt.ref)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Nil(t, got)
				assert.False(t, isLocal)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantLocal, isLocal)
			}
			if tt.wantRemoteCall {
				assert.Equal(t, 1, remoteCalls)
			} else {
				assert.Zero(t, remoteCalls)
			}
			if tt.wantDescriptor != nil {
				assert.Same(t, tt.wantDescriptor, got)
			}
			if tt.wantManifestCount > 0 {
				index, err := got.ImageIndex()
				require.NoError(t, err)
				manifest, err := index.IndexManifest()
				require.NoError(t, err)
				assert.Len(t, manifest.Manifests, tt.wantManifestCount)
			}
		})
	}
}

func TestCreatePreservedOnlyOCILayoutMaterializesBlobs(t *testing.T) {
	registryServer := httptest.NewServer(registry.New())
	t.Cleanup(registryServer.Close)

	registryRef, err := name.NewTag(registryServer.Listener.Addr().String()+"/test/image:latest", name.Insecure)
	require.NoError(t, err)
	image, err := random.Image(1024, 1)
	require.NoError(t, err)
	index := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add: image,
		Descriptor: remotev1.Descriptor{
			Platform: &remotev1.Platform{OS: "linux", Architecture: "amd64"},
		},
	})
	require.NoError(t, remote.WriteIndex(registryRef, index))

	originalLocal := tryGetManifestFromLocal
	originalRemote := getRemoteImageDescriptor
	t.Cleanup(func() {
		tryGetManifestFromLocal = originalLocal
		getRemoteImageDescriptor = originalRemote
	})
	tryGetManifestFromLocal = func(name.Reference) (*remote.Descriptor, remotev1.Hash, bool, error) {
		return nil, remotev1.Hash{}, false, errors.New("image is not available locally")
	}
	getRemoteImageDescriptor = remote.Get

	originalRef, err := reference.ParseNormalizedNamed(registryRef.String())
	require.NoError(t, err)
	outputDir := filepath.Join(t.TempDir(), "layout")
	err = createPreservedOnlyOCILayout(
		outputDir,
		[]types.PatchResult{{OriginalRef: originalRef}},
		[]types.PatchPlatform{{Platform: ispec.Platform{OS: "linux", Architecture: "amd64"}}},
	)
	require.NoError(t, err)

	layoutPath, err := layout.FromPath(outputDir)
	require.NoError(t, err)
	preservedIndex, err := layoutPath.ImageIndex()
	require.NoError(t, err)
	manifest, err := preservedIndex.IndexManifest()
	require.NoError(t, err)
	require.Len(t, manifest.Manifests, 1)
	preservedImage, err := preservedIndex.Image(manifest.Manifests[0].Digest)
	require.NoError(t, err)
	_, err = preservedImage.RawConfigFile()
	require.NoError(t, err)
	layers, err := preservedImage.Layers()
	require.NoError(t, err)
	require.Len(t, layers, 1)
	compressed, err := layers[0].Compressed()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, compressed.Close()) })
	_, err = io.Copy(io.Discard, compressed)
	require.NoError(t, err)
}

func TestDiscoverPlatformsMutableTagKeepsLocalPlatform(t *testing.T) {
	originalLocal := localImagePlatforms
	originalRemote := getRemoteImageDescriptor
	t.Cleanup(func() {
		localImagePlatforms = originalLocal
		getRemoteImageDescriptor = originalRemote
	})

	localImagePlatforms = func(context.Context, string) ([]ispec.Platform, bool, error) {
		return []ispec.Platform{{OS: "linux", Architecture: "arm64"}}, true, nil
	}
	getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
		t.Fatal("mutable local image reference must not be reconciled with a remote image")
		return nil, nil
	}

	platforms, err := DiscoverPlatformsFromReference("example.com/test/image:latest")
	require.NoError(t, err)
	require.Len(t, platforms, 1)
	assert.Equal(t, "arm64", platforms[0].Architecture)
}

func TestDiscoverPlatformsDigestReconcilesMatchingRemoteIndex(t *testing.T) {
	originalLocal := localImagePlatforms
	originalRemote := getRemoteImageDescriptor
	t.Cleanup(func() {
		localImagePlatforms = originalLocal
		getRemoteImageDescriptor = originalRemote
	})

	localImagePlatforms = func(context.Context, string) ([]ispec.Platform, bool, error) {
		return []ispec.Platform{{OS: "linux", Architecture: "arm64"}}, true, nil
	}
	getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
		return testRemoteIndexDescriptor("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"), nil
	}

	platforms, err := DiscoverPlatformsFromReference("example.com/test/image@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	require.NoError(t, err)
	require.Len(t, platforms, 2)
	assert.Equal(t, "amd64", platforms[0].Architecture)
	assert.Equal(t, "arm64", platforms[1].Architecture)
}

func TestDiscoverPlatformsDigestKeepsLocalPlatformWhenRemoteDigestDiffers(t *testing.T) {
	originalLocal := localImagePlatforms
	originalRemote := getRemoteImageDescriptor
	t.Cleanup(func() {
		localImagePlatforms = originalLocal
		getRemoteImageDescriptor = originalRemote
	})

	localImagePlatforms = func(context.Context, string) ([]ispec.Platform, bool, error) {
		return []ispec.Platform{{OS: "linux", Architecture: "arm64"}}, true, nil
	}
	getRemoteImageDescriptor = func(name.Reference, ...remote.Option) (*remote.Descriptor, error) {
		return testRemoteIndexDescriptor("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"), nil
	}

	platforms, err := DiscoverPlatformsFromReference("example.com/test/image@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
	require.NoError(t, err)
	require.Len(t, platforms, 1)
	assert.Equal(t, "arm64", platforms[0].Architecture)
}

func TestExtractFileFromStateWithLimit(t *testing.T) {
	const (
		path  = "/untrusted/file"
		limit = int64(4)
	)

	statFailure := errors.New("stat failed")
	readFailure := errors.New("read failed")
	tests := []struct {
		name          string
		stat          *fstypes.Stat
		statErr       error
		readData      []byte
		readErr       error
		want          []byte
		wantErr       error
		wantErrText   string
		wantRead      bool
		wantReadRange *gwclient.FileRange
	}{
		{
			name:          "exact boundary",
			stat:          &fstypes.Stat{Size: limit},
			readData:      []byte("data"),
			want:          []byte("data"),
			wantRead:      true,
			wantReadRange: &gwclient.FileRange{Offset: 0, Length: int(limit + 1)},
		},
		{
			name:        "oversized",
			stat:        &fstypes.Stat{Size: limit + 1},
			wantErrText: "exceeding the maximum allowed size of 4 bytes",
		},
		{
			name:        "missing",
			stat:        &fstypes.Stat{},
			statErr:     fs.ErrNotExist,
			wantErr:     fs.ErrNotExist,
			wantErrText: "unable to stat",
		},
		{
			name:        "stat failure",
			stat:        &fstypes.Stat{},
			statErr:     statFailure,
			wantErr:     statFailure,
			wantErrText: "unable to stat",
		},
		{
			name:          "read failure",
			stat:          &fstypes.Stat{Size: limit},
			readData:      []byte{},
			readErr:       readFailure,
			wantErr:       readFailure,
			wantErrText:   "unable to read",
			wantRead:      true,
			wantReadRange: &gwclient.FileRange{Offset: 0, Length: int(limit + 1)},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ref := &mocks.MockReference{}
			ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: path}).
				Return(test.stat, test.statErr).
				Once()
			if test.wantRead {
				ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{
					Filename: path,
					Range:    test.wantReadRange,
				}).Return(test.readData, test.readErr).Once()
			}

			result := gwclient.NewResult()
			result.SetRef(ref)
			client := &mocks.MockGWClient{}
			client.On("Solve", mock.Anything, mock.Anything).
				Return(result, nil).
				Once()
			state := llb.Scratch()

			got, err := ExtractFileFromStateWithLimit(t.Context(), client, &state, path, limit)
			if test.wantErr == nil && test.wantErrText == "" {
				require.NoError(t, err)
				assert.Equal(t, test.want, got)
			} else {
				require.Error(t, err)
				if test.wantErr != nil {
					require.ErrorIs(t, err, test.wantErr)
				}
				if test.wantErrText != "" {
					require.ErrorContains(t, err, test.wantErrText)
				}
			}

			client.AssertExpectations(t)
			ref.AssertExpectations(t)
			if !test.wantRead {
				ref.AssertNotCalled(t, "ReadFile", mock.Anything, mock.Anything)
			}
		})
	}
}

func TestReadFileWithLimitChunksGatewayResponses(t *testing.T) {
	const path = "/large/untrusted/file"

	firstChunk := make([]byte, int(maxGatewayReadFileChunkSize))
	for i := range firstChunk {
		firstChunk[i] = byte(i)
	}
	lastChunk := []byte("tail")
	fileSize := int64(len(firstChunk) + len(lastChunk))

	ref := &mocks.MockReference{}
	ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: path}).
		Return(&fstypes.Stat{Size: fileSize}, nil).
		Once()
	ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{
		Filename: path,
		Range: &gwclient.FileRange{
			Offset: 0,
			Length: int(maxGatewayReadFileChunkSize),
		},
	}).Return(firstChunk, nil).Once()
	ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{
		Filename: path,
		Range: &gwclient.FileRange{
			Offset: int(maxGatewayReadFileChunkSize),
			Length: len(lastChunk) + 1,
		},
	}).Return(lastChunk, nil).Once()

	got, err := ReadFileWithLimit(t.Context(), ref, path, fileSize)
	require.NoError(t, err)
	require.Len(t, got, int(fileSize))
	assert.Equal(t, firstChunk, got[:len(firstChunk)])
	assert.Equal(t, lastChunk, got[len(firstChunk):])
	ref.AssertExpectations(t)
}

func TestReadFileWithLimitUsesResolvedSymlinkSize(t *testing.T) {
	const (
		path  = "/etc/os-release"
		limit = int64(64)
	)
	contents := []byte("ID=ubuntu\nVERSION_ID=24.04\n")

	ref := &mocks.MockReference{}
	ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: path}).
		Return(&fstypes.Stat{Size: limit + 1, Mode: uint32(os.ModeSymlink)}, nil).
		Once()
	ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{
		Filename: path,
		Range:    &gwclient.FileRange{Offset: 0, Length: int(limit + 1)},
	}).Return(contents, nil).Once()

	got, err := ReadFileWithLimit(t.Context(), ref, path, limit)
	require.NoError(t, err)
	assert.Equal(t, contents, got)
	ref.AssertExpectations(t)
}

func TestReadFileWithLimitRejectsOversizedResolvedSymlink(t *testing.T) {
	const (
		path  = "/etc/os-release"
		limit = int64(4)
	)

	ref := &mocks.MockReference{}
	ref.On("StatFile", mock.Anything, gwclient.StatRequest{Path: path}).
		Return(&fstypes.Stat{Size: 1, Mode: uint32(os.ModeSymlink)}, nil).
		Once()
	ref.On("ReadFile", mock.Anything, gwclient.ReadRequest{
		Filename: path,
		Range:    &gwclient.FileRange{Offset: 0, Length: int(limit + 1)},
	}).Return([]byte("12345"), nil).Once()

	_, err := ReadFileWithLimit(t.Context(), ref, path, limit)
	require.ErrorContains(t, err, "exceeds the maximum allowed size of 4 bytes")
	ref.AssertExpectations(t)
}

func TestMatchingPlatformDescriptorUsesCompleteNormalizedIdentity(t *testing.T) {
	descriptor := func(hex string, platform ispec.Platform) remotev1.Descriptor {
		imagePlatform := remotev1.Platform{
			OS:           platform.OS,
			Architecture: platform.Architecture,
			Variant:      platform.Variant,
			OSVersion:    platform.OSVersion,
			OSFeatures:   platform.OSFeatures,
		}
		return remotev1.Descriptor{
			Digest:   remotev1.Hash{Algorithm: "sha256", Hex: hex},
			Platform: &imagePlatform,
		}
	}

	t.Run("arm64 v8 is equivalent to omitted variant", func(t *testing.T) {
		manifest := &remotev1.IndexManifest{Manifests: []remotev1.Descriptor{
			descriptor(strings.Repeat("a", 64), ispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}),
		}}
		target := ispec.Platform{OS: "linux", Architecture: "arm64"}
		got, err := matchingPlatformDescriptor(manifest, &target)
		require.NoError(t, err)
		assert.Equal(t, strings.Repeat("a", 64), got.Digest.Hex)
	})

	t.Run("os version and features must match", func(t *testing.T) {
		manifest := &remotev1.IndexManifest{Manifests: []remotev1.Descriptor{
			descriptor(strings.Repeat("a", 64), ispec.Platform{
				OS: "windows", Architecture: "amd64", OSVersion: "10.0.1", OSFeatures: []string{"win32k"},
			}),
			descriptor(strings.Repeat("b", 64), ispec.Platform{
				OS: "windows", Architecture: "amd64", OSVersion: "10.0.2", OSFeatures: []string{"gpu", "win32k"},
			}),
		}}
		target := ispec.Platform{
			OS: "windows", Architecture: "amd64", OSVersion: "10.0.2", OSFeatures: []string{"win32k", "gpu"},
		}
		got, err := matchingPlatformDescriptor(manifest, &target)
		require.NoError(t, err)
		assert.Equal(t, strings.Repeat("b", 64), got.Digest.Hex)
	})

	t.Run("empty variant is not a wildcard", func(t *testing.T) {
		manifest := &remotev1.IndexManifest{Manifests: []remotev1.Descriptor{
			descriptor(strings.Repeat("a", 64), ispec.Platform{OS: "linux", Architecture: "arm", Variant: "v6"}),
		}}
		target := ispec.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}
		_, err := matchingPlatformDescriptor(manifest, &target)
		require.ErrorContains(t, err, "contains no descriptor")
	})

	t.Run("ambiguous normalized matches fail", func(t *testing.T) {
		manifest := &remotev1.IndexManifest{Manifests: []remotev1.Descriptor{
			descriptor(strings.Repeat("a", 64), ispec.Platform{OS: "linux", Architecture: "arm64"}),
			descriptor(strings.Repeat("b", 64), ispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}),
		}}
		target := ispec.Platform{OS: "linux", Architecture: "arm64"}
		_, err := matchingPlatformDescriptor(manifest, &target)
		require.ErrorContains(t, err, "multiple descriptors")
	})
}

func TestAddOCIExportMetadata(t *testing.T) {
	result := gwclient.NewResult()
	metadata := platformExportMetadata{
		Config: []byte(`{"architecture":"arm64","os":"linux","config":{"User":"101"}}`),
		Annotations: map[string]string{
			"sh.copa.chisel.release": "ubuntu-24.04",
			"sh.copa.chisel.version": "v1.4.2",
		},
	}

	require.NoError(t, addOCIExportMetadata(result, metadata))
	assert.Equal(t, metadata.Config, result.Metadata[exptypes.ExporterImageConfigKey])
	for key, value := range metadata.Annotations {
		assert.Equal(t, []byte(value), result.Metadata[exptypes.AnnotationManifestKey(nil, key)])
	}
}

const (
	goosDarwin  = "darwin"
	goosWindows = "windows"
)

type mockControlServer struct {
	controlapi.ControlServer
}

func (s *mockControlServer) ListWorkers(context.Context, *controlapi.ListWorkersRequest) (*controlapi.ListWorkersResponse, error) {
	return &controlapi.ListWorkersResponse{
		Record: []*bk_types.WorkerRecord{},
	}, nil
}

func (s *mockControlServer) Session(controlapi.Control_SessionServer) error {
	return nil
}

func (s *mockControlServer) Status(*controlapi.StatusRequest, controlapi.Control_StatusServer) error {
	return nil
}

func (s *mockControlServer) Solve(context.Context, *controlapi.SolveRequest) (*controlapi.SolveResponse, error) {
	return &controlapi.SolveResponse{}, nil
}

type mockLLBBridgeServer struct {
	gateway.LLBBridgeServer
	caps []*caps.APICap
}

func (m *mockLLBBridgeServer) Ping(context.Context, *gateway.PingRequest) (*gateway.PongResponse, error) {
	return &gateway.PongResponse{
		FrontendAPICaps: m.caps,
		LLBCaps:         m.caps,
	}, nil
}

func (m *mockLLBBridgeServer) Solve(context.Context, *gateway.SolveRequest) (*gateway.SolveResponse, error) {
	return &gateway.SolveResponse{}, nil
}

func makeCapList(capIDs ...apicaps.CapID) []*caps.APICap {
	var (
		ls   apicaps.CapList
		caps = make([]apicaps.Cap, 0, len(capIDs))
	)

	for _, id := range capIDs {
		caps = append(caps, apicaps.Cap{
			ID:      id,
			Enabled: true,
		})
	}

	ls.Init(caps...)
	return ls.All()
}

func newMockBuildkitAPI(t *testing.T, caps ...apicaps.CapID) string {
	// Use a shorter path strategy that works across platforms
	var sockPath string
	if runtime.GOOS == goosDarwin {
		// On macOS, use /tmp directly for shorter paths to avoid socket path length limits
		sockPath = filepath.Join(utils.DefaultTempWorkingFolder, fmt.Sprintf("bk-%d.sock", time.Now().UnixNano()))
	} else {
		// On other platforms, use temp dir but with shorter name
		tmp := t.TempDir()
		sockPath = filepath.Join(tmp, "bk.sock")
	}

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		l.Close()
		if runtime.GOOS == goosDarwin {
			os.Remove(sockPath) // Clean up manually on macOS since we're not using TempDir
		}
	})

	srv := grpc.NewServer()
	t.Cleanup(srv.Stop)

	capList := makeCapList(caps...)
	gateway.RegisterLLBBridgeServer(srv, &mockLLBBridgeServer{
		LLBBridgeServer: &gateway.UnimplementedLLBBridgeServer{},
		caps:            capList,
	})

	control := &mockControlServer{
		ControlServer: &controlapi.UnimplementedControlServer{},
	}
	controlapi.RegisterControlServer(srv, control)

	go srv.Serve(l) // nolint:errcheck

	return l.Addr().String()
}

func unwrapErrors(err error) []error {
	// `errors.Unwrap` uses this interface
	// buildkit errors may be wrapped in this
	type stdUnwrap interface {
		Unwrap() error
	}

	// The type used by `errors.Join` uses this interface
	type joinedUnwrap interface {
		Unwrap() []error
	}

	var out []error
	switch v := err.(type) {
	case stdUnwrap:
		return unwrapErrors(v.Unwrap())
	case joinedUnwrap:
		for _, e := range v.Unwrap() {
			// multiple calls to `errors.Join` may result in nested wraps, so recurse on those errors
			out = append(out, unwrapErrors(e)...)
		}
	default:
		out = append(out, err)
	}

	return out
}

func checkMissingCapsError(t *testing.T, err error, caps ...apicaps.CapID) {
	t.Helper()
	lsErr := unwrapErrors(err)
	found := make(map[apicaps.CapID]bool, len(caps))
	for _, err := range lsErr {
		check := &apicaps.CapError{}
		if errors.As(err, &check) {
			found[check.ID] = true
		}
	}
	if len(found) != len(caps) {
		t.Errorf("expected %d errors, got: %d", len(caps), len(found))
		t.Error(lsErr)
	}
}

func TestGetServerNameFromAddr(t *testing.T) {
	testCases := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "hostname",
			addr: "tcp://hostname:1234",
			want: "hostname",
		},
		{
			name: "IP address",
			addr: "tcp://127.0.0.1:1234",
			want: "127.0.0.1",
		},
		{
			name: "invalid URL",
			addr: "hostname:1234",
			want: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := getServerNameFromAddr(tc.addr)
			if got != tc.want {
				t.Errorf("getServerNameFromAddr(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	ctx := context.Background()

	t.Run("custom buildkit addr", func(t *testing.T) {
		t.Run("missing caps", func(t *testing.T) {
			t.Parallel()
			addr := newMockBuildkitAPI(t)
			ctxT, cancel := context.WithTimeout(ctx, time.Second)
			bkOpts := Opts{
				Addr: "unix://" + addr,
			}
			client, err := NewClient(ctxT, bkOpts)
			cancel()
			assert.NoError(t, err)
			defer client.Close()

			ctxT, cancel = context.WithTimeout(ctx, time.Second)
			err = ValidateClient(ctxT, client)
			cancel()
			checkMissingCapsError(t, err, requiredCaps...)
		})
		t.Run("Invalid key path", func(t *testing.T) {
			t.Parallel()
			addr := newMockBuildkitAPI(t)
			ctxT, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			bkOpts := Opts{
				Addr:    `https://` + addr,
				KeyPath: `No-Keys-Exist/Here`,
			}
			_, err := NewClient(ctxT, bkOpts)
			assert.ErrorContains(t, err, "could not read certificate/key")
		})
		t.Run("with caps", func(t *testing.T) {
			t.Parallel()
			addr := newMockBuildkitAPI(t, requiredCaps...)

			ctxT, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			bkOpts := Opts{
				Addr: "unix://" + addr,
			}
			client, err := NewClient(ctxT, bkOpts)
			assert.NoError(t, err)
			defer client.Close()

			err = ValidateClient(ctxT, client)
			assert.NoError(t, err)
		})
		t.Run("default buildkit addr", func(t *testing.T) {
			t.Parallel()
			bkOpts := Opts{} // Initialize with default values
			client, err := NewClient(context.TODO(), bkOpts)
			assert.NoError(t, err)
			defer client.Close()
			err = ValidateClient(context.TODO(), client)
			assert.NoError(t, err)
		})
	})
}

func TestArrayFile(t *testing.T) {
	type spec struct {
		desc     string
		input    []string
		expected string
	}

	tests := []spec{
		{
			desc:     "single element, must have newline at the end of the file",
			input:    []string{"line"},
			expected: "line\n",
		},
		{
			desc:     "multiple elements, must have newline at the end of the file",
			input:    []string{"line", "another"},
			expected: "line\nanother\n",
		},
		{
			desc:     "empty array produces empty file",
			input:    []string{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			b := ArrayFile(tt.input)
			assert.Equal(t, tt.expected, string(b))
		})
	}
}

func TestSetupLabels(t *testing.T) {
	tests := []struct {
		testName      string
		configData    []byte
		expectBaseImg string
		expectImage   string
		expectError   bool
	}{
		{
			"No labels",
			[]byte(`{"config": {}}`),
			"",
			"test_image",
			false,
		},
		{
			"Labels no base",
			[]byte(`{"config": {"labels": {}}}`),
			"",
			"test_image",
			false,
		},
		{
			"Labels with base image",
			[]byte(`{"config": {"labels": {"BaseImage": "existing_base_image"}}}`),
			"existing_base_image",
			"existing_base_image",
			false,
		},
		{
			"Invalid JSON",
			[]byte(`{"config": {"labels": {"BaseImage": "existing_base_image"}`),
			"",
			"",
			true,
		},
	}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			image := "test_image"
			baseImage, updatedConfigData, _ := setupLabels(image, test.configData)

			if test.expectError {
				assert.Equal(t, "", baseImage)
				assert.Nil(t, updatedConfigData)
			} else {
				assert.Equal(t, test.expectBaseImg, baseImage)

				var updatedConfig ispec.Image
				err := json.Unmarshal(updatedConfigData, &updatedConfig)
				assert.NoError(t, err)
				assert.Equal(t, test.expectImage, updatedConfig.Config.Labels["BaseImage"])
			}
		})
	}
}

func TestSetupLabelsPreservesBaseImageThroughAnnotationMerge(t *testing.T) {
	const image = "registry.example.com/application:latest"
	input := []byte(`{"config":{"Labels":{"existing":"preserved"}}}`)

	baseImage, withBaseImage, err := setupLabels(image, input)
	require.NoError(t, err)
	assert.Empty(t, baseImage)

	updated, err := AddImageConfigLabels(withBaseImage, map[string]string{
		"sh.copa.chisel.release": "ubuntu-24.04",
	})
	require.NoError(t, err)

	var config ispec.Image
	require.NoError(t, json.Unmarshal(updated, &config))
	assert.Equal(t, image, config.Config.Labels["BaseImage"])
	assert.Equal(t, "preserved", config.Config.Labels["existing"])
	assert.Equal(t, "ubuntu-24.04", config.Config.Labels["sh.copa.chisel.release"])
}

func TestUpdateImageConfigData(t *testing.T) {
	ctx := context.Background()

	t.Run("No base image", func(t *testing.T) {
		mockClient := &mocks.MockGWClient{}
		configData := []byte(`{"config": {"labels": {"com.example.label": "value"}}}`)
		expectedData := []byte(`{"config": {"labels": {"com.example.label": "value"}, {"BaseImage": "myimage:latest"}}}`)
		image := "myimage:latest"

		resultConfig, resultPatched, resultImage, err := updateImageConfigData(ctx, mockClient, configData, image)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if reflect.DeepEqual(expectedData, configData) {
			t.Errorf("Expected config data to be %s, got %s", configData, resultConfig)
		}

		if resultPatched != nil {
			t.Errorf("Expected patched config to be nil, got %s", resultPatched)
		}

		if resultImage != image {
			t.Errorf("Expected image to be %s, got %s", image, resultImage)
		}
	})

	t.Run("With base image", func(t *testing.T) {
		mockClient := &mocks.MockGWClient{}
		mockClient.On("ResolveImageConfig",
			mock.Anything, mock.AnythingOfType("string"), mock.Anything).
			Return("imageConfigString", digest.Digest("digest"), []byte(`{"config": {"labels": {"BaseImage": "rockylinux:latest"}}}`), nil)

		configData := []byte(`{"config": {"labels": {"BaseImage": "rockylinux:latest"}}}`)
		image := "rockylinux:latest"

		resultConfig, _, resultImage, err := updateImageConfigData(ctx, mockClient, configData, image)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		expectedConfig := []byte(`{"config":{"labels":{"BaseImage":"rockylinux:latest"}}}`)
		if !reflect.DeepEqual(resultConfig, expectedConfig) {
			t.Errorf("Expected config data to be %s, got %s", expectedConfig, resultConfig)
		}

		if resultImage != "rockylinux:latest" {
			t.Errorf("Expected image to be baseimage:latest, got %s", resultImage)
		}

		mockClient.AssertExpectations(t)
	})
}

func TestMapGoArch(t *testing.T) {
	cases := []struct {
		arch, variant, want string
	}{
		{"amd64", "", "x86_64"},
		{"386", "", "i386"},
		{"arm", "v7", "arm"},
		{"arm", "v5eb", "armeb"},
		{"mips64", "n32", "mipsn32"},
		{"mips64", "", "mips64"},
		{"ppc64", "le", "ppc64le"},
		{"loong64", "", "loongarch64"},
		{"xtensa", "eb", "xtensaeb"},
		{"unknown", "", "unknown"},
	}
	for _, c := range cases {
		got := mapGoArch(c.arch, c.variant)
		if got != c.want {
			t.Errorf("mapGoArch(%q,%q) = %q, want %q", c.arch, c.variant, got, c.want)
		}
	}
}

func TestIsSupportedOsType(t *testing.T) {
	supported := []string{
		utils.OSTypeAlpine,
		utils.OSTypeDebian,
		utils.OSTypeUbuntu,
		utils.OSTypeCBLMariner,
		utils.OSTypeAzureLinux,
		utils.OSTypeCentOS,
		utils.OSTypeOracle,
		utils.OSTypeRedHat,
		utils.OSTypeRocky,
		utils.OSTypeAmazon,
		utils.OSTypeAlma,
		utils.OSTypeSLES,
		utils.OSTypeOpenSUSELeap,
		utils.OSTypeOpenSUSETW,
	}
	for _, os := range supported {
		if !isSupportedOsType(os) {
			t.Errorf("expected %s to be supported", os)
		}
	}

	// Test non-canonical inputs that should be canonicalized to supported types
	// This tests the integration with utils.CanonicalOSType
	nonCanonicalSupported := []string{
		"opensuse leap",       // space variant (older Trivy versions)
		"opensuse tumbleweed", // space variant (older Trivy versions)
		"opensuse.leap",       // dot variant
		"opensuse.tumbleweed", // dot variant
		"suse linux enterprise server",
		"SLES",
		"openSUSE Leap",
		"openSUSE Tumbleweed",
	}
	for _, os := range nonCanonicalSupported {
		if !isSupportedOsType(os) {
			t.Errorf("expected non-canonical %q to be supported after canonicalization", os)
		}
	}

	unsupported := []string{"windows", "freebsd", "plan9"}
	for _, os := range unsupported {
		if isSupportedOsType(os) {
			t.Errorf("did not expect %s to be supported", os)
		}
	}
}

// minimal DirEntry impl.
type fakeEntry string

func (f fakeEntry) Name() string             { return string(f) }
func (fakeEntry) IsDir() bool                { return false }
func (fakeEntry) Type() fs.FileMode          { return 0 }
func (fakeEntry) Info() (fs.FileInfo, error) { return nil, nil }

func TestQemuAvailable_Mocked(t *testing.T) {
	platArm := &types.PatchPlatform{Platform: ispec.Platform{OS: "linux", Architecture: "arm64"}}
	platAmd := &types.PatchPlatform{Platform: ispec.Platform{OS: "linux", Architecture: "amd64"}}

	tests := []struct {
		name     string
		plat     *types.PatchPlatform
		stubDir  func(string) ([]os.DirEntry, error)
		stubRead func(string) ([]byte, error)
		stubPath func(string) (string, error)
		want     bool
	}{
		{
			name: "nil platform", plat: nil,
			want: false,
		},
		{
			name: "binfmt_misc match", plat: platArm,
			stubDir:  func(string) ([]os.DirEntry, error) { return []os.DirEntry{fakeEntry("arm")}, nil },
			stubRead: func(string) ([]byte, error) { return []byte("interpreter /usr/bin/qemu-aarch64"), nil },
			stubPath: func(string) (string, error) { return "", os.ErrNotExist },
			want:     true,
		},
		{
			name: "lookPath fallback", plat: platArm,
			stubDir:  func(string) ([]os.DirEntry, error) { return []os.DirEntry{}, nil },
			stubRead: func(string) ([]byte, error) { return nil, nil },
			stubPath: func(string) (string, error) { return "/usr/bin/qemu-aarch64-static", nil },
			want:     true,
		},
		{
			name: "no match at all", plat: platAmd,
			stubDir:  func(string) ([]os.DirEntry, error) { return []os.DirEntry{}, nil },
			stubRead: func(string) ([]byte, error) { return nil, nil },
			stubPath: func(string) (string, error) { return "", os.ErrNotExist },
			want:     runtime.GOOS == goosDarwin || runtime.GOOS == goosWindows, // true on macOS/Windows due to Docker Desktop assumption
		},
	}

	// store originals
	origDir, origRead, origPath := readDir, readFile, lookPath
	defer func() { readDir, readFile, lookPath = origDir, origRead, origPath }()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// override or reset mocks per case
			if tc.stubDir != nil {
				readDir = tc.stubDir
			} else {
				readDir = origDir
			}
			if tc.stubRead != nil {
				readFile = tc.stubRead
			} else {
				readFile = origRead
			}
			if tc.stubPath != nil {
				lookPath = tc.stubPath
			} else {
				lookPath = origPath
			}

			got := QemuAvailable(tc.plat)
			if got != tc.want {
				t.Fatalf("QemuAvailable() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOCIPlatformExportMetadataRewritesVersionAnnotation(t *testing.T) {
	tests := []struct {
		name       string
		patchedRef string
		want       string
	}{
		{
			name:       "patched tag contains original version",
			patchedRef: "example.com/app:1.0.0-patched-amd64",
			want:       "1.0.0-patched-amd64",
		},
		{
			name:       "patched tag is a suffix",
			patchedRef: "example.com/app:patched-amd64",
			want:       "1.0.0-patched-amd64",
		},
		{
			name:       "coincidental substring is not a version component",
			patchedRef: "example.com/app:11.0.0-patched",
			want:       "1.0.0-11.0.0-patched",
		},
		{
			name:       "version component after separator uses patched tag",
			patchedRef: "example.com/app:release-1.0.0-patched",
			want:       "release-1.0.0-patched",
		},
		{
			name:       "v-prefixed version uses patched tag",
			patchedRef: "example.com/app:v1.0.0-patched",
			want:       "v1.0.0-patched",
		},
		{
			name:       "v-prefixed version after separator uses patched tag",
			patchedRef: "example.com/app:release-v1.0.0-patched",
			want:       "release-v1.0.0-patched",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patchedRef, err := reference.ParseNormalizedNamed(tt.patchedRef)
			require.NoError(t, err)
			originalVersion := "1.0.0"
			annotations := map[string]string{
				"org.opencontainers.image.source":  "https://example.com/source",
				"org.opencontainers.image.version": originalVersion,
			}
			result := &types.PatchResult{
				PatchedRef: patchedRef,
				PatchedDesc: &ispec.Descriptor{
					Annotations: annotations,
				},
				ConfigData: []byte("config"),
			}

			metadata := ociPlatformExportMetadata(result)

			assert.Equal(t, []byte("config"), metadata.Config)
			assert.Equal(t, tt.want, metadata.Annotations["org.opencontainers.image.version"])
			assert.Equal(t, "https://example.com/source", metadata.Annotations["org.opencontainers.image.source"])
			assert.Equal(t, originalVersion, annotations["org.opencontainers.image.version"], "source descriptor annotations must remain unchanged")
		})
	}
}

func TestOCIExporterAttrs(t *testing.T) {
	tests := []struct {
		name                 string
		exportOpts           OCILayoutExportOptions
		wantCompression      string
		wantForceCompression bool
	}{
		{
			name: "no compression options",
		},
		{
			name: "compression without force compression",
			exportOpts: OCILayoutExportOptions{
				Compression: "zstd",
			},
			wantCompression: "zstd",
		},
		{
			name: "compression with force compression",
			exportOpts: OCILayoutExportOptions{
				Compression:      "gzip",
				ForceCompression: true,
			},
			wantCompression:      "gzip",
			wantForceCompression: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs := ociExporterAttrs(tc.exportOpts)

			assert.Equal(t, "true", attrs["oci-mediatypes"])
			assert.Equal(t, "false", attrs["buildinfo"])
			if tc.wantCompression == "" {
				assert.NotContains(t, attrs, "compression")
			} else {
				assert.Equal(t, tc.wantCompression, attrs["compression"])
			}
			_, hasForceCompression := attrs["force-compression"]
			assert.Equal(t, tc.wantForceCompression, hasForceCompression)
		})
	}
}

func TestHasOCILayoutInputs(t *testing.T) {
	t.Parallel()

	state := llb.Scratch()
	tests := []struct {
		name      string
		results   []types.PatchResult
		platforms []types.PatchPlatform
		want      bool
	}{
		{name: "none"},
		{
			name:    "patched state",
			results: []types.PatchResult{{PatchedState: &state}},
			want:    true,
		},
		{
			name: "preserved platform",
			platforms: []types.PatchPlatform{{
				Platform:       ispec.Platform{OS: "linux", Architecture: "amd64"},
				ShouldPreserve: true,
			}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, hasOCILayoutInputs(tt.results, tt.platforms))
		})
	}
}

func TestPlatformsFromIndexManifest(t *testing.T) {
	linux := func(arch, variant string) *remotev1.Platform {
		return &remotev1.Platform{OS: "linux", Architecture: arch, Variant: variant}
	}

	manifest := &remotev1.IndexManifest{
		Manifests: []remotev1.Descriptor{
			{Platform: linux("amd64", "")},
			{Platform: nil}, // e.g. attestation or provenance entry
			{Platform: linux("arm64", "v8")},
			{Platform: &remotev1.Platform{OS: "unknown", Architecture: "unknown"}},
		},
	}

	got := platformsFromIndexManifest(manifest)

	want := []types.PatchPlatform{
		{Platform: ispec.Platform{OS: "linux", Architecture: "amd64"}},
		{Platform: ispec.Platform{OS: "linux", Architecture: "arm64"}}, // v8 variant stripped
	}
	assert.Equal(t, want, got)
}
