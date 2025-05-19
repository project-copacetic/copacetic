package imageloader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	dockerTypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	dockerClient "github.com/docker/docker/client"
)

func TestDockerLoader_Load_Success(t *testing.T) {
	ctx := context.Background()
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (image.LoadResponse, error) {
			return image.LoadResponse{
				Body: io.NopCloser(strings.NewReader("{\"stream\":\"Step 1/2\"}\n{\"stream\":\"Successfully loaded image: myimage:latest\"}\n")),
				JSON: true,
			}, nil
		},
	}
	ldr := &dockerLoader{cli: mockCli}

	err := ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err != nil {
		t.Fatalf("(*dockerLoader).Load failed for success case: %v", err)
	}
}

func TestDockerLoader_Load_ImageLoadReturnsError(t *testing.T) {
	ctx := context.Background()
	expectedErr := errors.New("simulated docker client ImageLoad error")
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (image.LoadResponse, error) {
			return image.LoadResponse{}, expectedErr
		},
	}
	ldr := &dockerLoader{cli: mockCli}

	err := ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error '%v', got '%v'", expectedErr, err)
	}
}

func TestDockerLoader_Load_DaemonJsonErrorField(t *testing.T) {
	ctx := context.Background()
	errMsg := "daemon error via 'error' field"
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (image.LoadResponse, error) {
			// structure matching what dockerLoader.Load expects for JSON errors
			errJSON := fmt.Sprintf(`{"error": "%s"}`, errMsg)
			return image.LoadResponse{
				Body: io.NopCloser(strings.NewReader(errJSON + "\n")),
				JSON: true,
			}, nil
		},
	}
	ldr := &dockerLoader{cli: mockCli}

	err := ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err == nil {
		t.Fatal("expected an error from daemon JSON, got nil")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("error message '%v' did not contain expected '%s'", err, errMsg)
	}
}

func TestDockerLoader_Load_DaemonJsonErrorResponseField(t *testing.T) {
	ctx := context.Background()
	errMsg := "daemon error via 'errorResponse' field"
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (image.LoadResponse, error) {
			errJSON := fmt.Sprintf(`{"errorDetail":{"message":"%s"}, "errorResponse":{"message":"%s"}}`, errMsg, errMsg)
			return image.LoadResponse{
				Body: io.NopCloser(strings.NewReader(errJSON + "\n")),
				JSON: true,
			}, nil
		},
	}
	ldr := &dockerLoader{cli: mockCli}

	err := ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err == nil {
		t.Fatal("expected an error from daemon JSON (errorResponse), got nil")
	}
	if !strings.Contains(err.Error(), errMsg) {
		t.Fatalf("error message '%v' did not contain expected '%s'", err, errMsg)
	}
}

func TestDockerLoader_Load_BodyScanError(t *testing.T) {
	ctx := context.Background()
	scanErr := errors.New("simulated scanner error")
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (image.LoadResponse, error) {
			return image.LoadResponse{
				Body: io.NopCloser(&mockErrorReader{readErr: scanErr}),
				JSON: true,
			}, nil
		},
	}
	ldr := &dockerLoader{cli: mockCli}

	err := ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err != nil {
		t.Fatalf("(*dockerLoader).Load expected to return nil on scanner error (error is logged, not returned), got: %v", err)
	}
}

func TestDockerLoader_Load_NonJsonInLastLineButRespJsonTrue(t *testing.T) {
	ctx := context.Background()
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (image.LoadResponse, error) {
			return image.LoadResponse{
				Body: io.NopCloser(strings.NewReader("This is not JSON\n")),
				JSON: true,
			}, nil
		},
	}
	ldr := &dockerLoader{cli: mockCli}

	err := ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err != nil {
		t.Fatalf("(*dockerLoader).Load expected nil error when last line is not JSON despite Resp.JSON=true, got: %v", err)
	}
}

func TestDockerLoader_Load_RespJsonFalse(t *testing.T) {
	ctx := context.Background()
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (image.LoadResponse, error) {
			return image.LoadResponse{
				Body: io.NopCloser(strings.NewReader("Some progress line\nFinal non-JSON output\n")),
				JSON: false,
			}, nil
		},
	}
	ldr := &dockerLoader{cli: mockCli}

	err := ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err != nil {
		t.Fatalf("(*dockerLoader).Load expected nil error when Resp.JSON=false, got: %v", err)
	}
}

func TestDockerLoader_Load_EmptyStream(t *testing.T) {
	ctx := context.Background()
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (image.LoadResponse, error) {
			return image.LoadResponse{
				Body: io.NopCloser(strings.NewReader("")),
				JSON: true,
			}, nil
		},
	}
	ldr := &dockerLoader{cli: mockCli}
	// lastLine will be ""
	// JSON parsing will not happen or will not find an error
	err := ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err != nil {
		t.Fatalf("(*dockerLoader).Load expected nil error for empty stream with JSON=true, got: %v", err)
	}

	mockCli.imageLoadFunc = func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (image.LoadResponse, error) {
		return image.LoadResponse{
			Body: io.NopCloser(strings.NewReader("")),
			JSON: false,
		}, nil
	}
	ldr = &dockerLoader{cli: mockCli}
	err = ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err != nil {
		t.Fatalf("(*dockerLoader).Load expected nil error for empty stream with JSON=false, got: %v", err)
	}
}

// mockDockerAPIClientImpl implements the dockerAPIClient interface for testing.
type mockDockerAPIClientImpl struct {
	pingFunc      func(ctx context.Context) (dockerTypes.Ping, error)
	imageLoadFunc func(ctx context.Context, input io.Reader, loadOpts ...dockerClient.ImageLoadOption) (image.LoadResponse, error)
}

func (m *mockDockerAPIClientImpl) Ping(ctx context.Context) (dockerTypes.Ping, error) {
	if m.pingFunc != nil {
		return m.pingFunc(ctx)
	}
	return dockerTypes.Ping{APIVersion: "mocked-api"}, nil
}

func (m *mockDockerAPIClientImpl) ImageLoad(ctx context.Context, input io.Reader, loadOpts ...dockerClient.ImageLoadOption) (image.LoadResponse, error) {
	_, _ = io.Copy(io.Discard, input)
	if m.imageLoadFunc != nil {
		return m.imageLoadFunc(ctx, input, loadOpts...)
	}
	// if no specific mock function is provided
	return image.LoadResponse{
		Body: io.NopCloser(strings.NewReader("{\"stream\":\"Default mock: Successfully loaded image\"}\n")),
		JSON: true,
	}, nil
}

// mockErrorReader helps simulate errors during io.Reader operations.
type mockErrorReader struct {
	readErr error
	content *strings.Reader
}

func (m *mockErrorReader) Read(p []byte) (n int, err error) {
	if m.content != nil && m.content.Len() > 0 {
		return m.content.Read(p)
	}
	return 0, m.readErr
}
