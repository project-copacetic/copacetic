package imageloader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	dockerClient "github.com/moby/moby/client"
)

func TestDockerLoader_Load_Success(t *testing.T) {
	ctx := context.Background()
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (dockerClient.ImageLoadResult, error) {
			return io.NopCloser(strings.NewReader("{\"stream\":\"Step 1/2\"}\n{\"stream\":\"Successfully loaded image: myimage:latest\"}\n")), nil
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
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (dockerClient.ImageLoadResult, error) {
			return nil, expectedErr
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
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (dockerClient.ImageLoadResult, error) {
			errJSON := fmt.Sprintf(`{"error": "%s"}`, errMsg)
			return io.NopCloser(strings.NewReader(errJSON + "\n")), nil
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

func TestDockerLoader_Load_BodyScanError(t *testing.T) {
	ctx := context.Background()
	scanErr := errors.New("simulated scanner error")
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (dockerClient.ImageLoadResult, error) {
			return io.NopCloser(&mockErrorReader{readErr: scanErr}), nil
		},
	}
	ldr := &dockerLoader{cli: mockCli}

	err := ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err != nil {
		t.Fatalf("(*dockerLoader).Load expected to return nil on scanner error (error is logged, not returned), got: %v", err)
	}
}

func TestDockerLoader_Load_NonJsonInLastLine(t *testing.T) {
	ctx := context.Background()
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (dockerClient.ImageLoadResult, error) {
			return io.NopCloser(strings.NewReader("This is not JSON\n")), nil
		},
	}
	ldr := &dockerLoader{cli: mockCli}

	err := ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err != nil {
		t.Fatalf("(*dockerLoader).Load expected nil error when last line is not JSON, got: %v", err)
	}
}

func TestDockerLoader_Load_EmptyStream(t *testing.T) {
	ctx := context.Background()
	mockCli := &mockDockerAPIClientImpl{
		imageLoadFunc: func(_ context.Context, _ io.Reader, _ ...dockerClient.ImageLoadOption) (dockerClient.ImageLoadResult, error) {
			return io.NopCloser(strings.NewReader("")), nil
		},
	}
	ldr := &dockerLoader{cli: mockCli}

	err := ldr.Load(ctx, bytes.NewReader([]byte("dummy_tar_data")), "unused-image-ref")
	if err != nil {
		t.Fatalf("(*dockerLoader).Load expected nil error for empty stream, got: %v", err)
	}
}

// mockDockerAPIClientImpl implements the dockerAPIClient interface for testing.
type mockDockerAPIClientImpl struct {
	pingFunc      func(ctx context.Context, options dockerClient.PingOptions) (dockerClient.PingResult, error)
	imageLoadFunc func(ctx context.Context, input io.Reader, loadOpts ...dockerClient.ImageLoadOption) (dockerClient.ImageLoadResult, error)
}

func (m *mockDockerAPIClientImpl) Ping(ctx context.Context, options dockerClient.PingOptions) (dockerClient.PingResult, error) {
	if m.pingFunc != nil {
		return m.pingFunc(ctx, options)
	}
	return dockerClient.PingResult{APIVersion: "mocked-api"}, nil
}

func (m *mockDockerAPIClientImpl) ImageLoad(ctx context.Context, input io.Reader, loadOpts ...dockerClient.ImageLoadOption) (dockerClient.ImageLoadResult, error) {
	_, _ = io.Copy(io.Discard, input)
	if m.imageLoadFunc != nil {
		return m.imageLoadFunc(ctx, input, loadOpts...)
	}
	return io.NopCloser(strings.NewReader("{\"stream\":\"Default mock: Successfully loaded image\"}\n")), nil
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
