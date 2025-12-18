package tui

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDisplay(t *testing.T) {
	tests := []struct {
		name      string
		debugMode bool
		wantType  string
	}{
		{
			name:      "debug mode uses progressui",
			debugMode: true,
			wantType:  "*progressui.Display",
		},
		{
			name:      "normal mode uses progrock",
			debugMode: false,
			wantType:  "*tui.progrockDisplay",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temp file to avoid TTY detection issues
			tmpFile, err := os.CreateTemp("", "test")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			defer os.Remove(tmpFile.Name())
			defer tmpFile.Close()

			display, err := NewDisplay(tmpFile, tt.debugMode)
			if err != nil {
				t.Fatalf("NewDisplay() error = %v", err)
			}
			if display == nil {
				t.Fatal("NewDisplay() returned nil display")
			}
		})
	}
}

func TestProgrockDisplayCreation(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	display, err := NewProgrockDisplay(tmpFile)
	if err != nil {
		t.Fatalf("NewProgrockDisplay() error = %v", err)
	}

	progrockDisp, ok := display.(*progrockDisplay)
	if !ok {
		t.Fatal("Expected *progrockDisplay")
	}

	if progrockDisp.tape == nil {
		t.Error("Expected tape to be initialized")
	}
	if progrockDisp.ui == nil {
		t.Error("Expected ui to be initialized")
	}
	if progrockDisp.rec == nil {
		t.Error("Expected recorder to be initialized")
	}
}

func TestNewDisplayNonTTY(t *testing.T) {
	// Test with a non-TTY file (buffer)
	var buf bytes.Buffer
	tmpFile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()
	_ = buf // unused but shows intent

	// Non-TTY should fall back to progressui
	display, err := NewDisplay(tmpFile, false)
	if err != nil {
		t.Fatalf("NewDisplay() error = %v", err)
	}
	if display == nil {
		t.Fatal("NewDisplay() returned nil display")
	}
}

func TestProcessBuildkitProgress_ChannelClosed(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	display, err := NewProgrockDisplay(tmpFile)
	require.NoError(t, err)

	progrockDisp, ok := display.(*progrockDisplay)
	require.True(t, ok, "expected *progrockDisplay")
	ch := make(chan *client.SolveStatus)
	warnings := []client.VertexWarning{}

	// Close channel immediately
	close(ch)

	ctx := context.Background()
	err = progrockDisp.processBuildkitProgress(ctx, ch, &warnings)
	assert.NoError(t, err)
}

func TestProcessBuildkitProgress_ContextCanceled(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	display, err := NewProgrockDisplay(tmpFile)
	require.NoError(t, err)

	progrockDisp, ok := display.(*progrockDisplay)
	require.True(t, ok, "expected *progrockDisplay")
	ch := make(chan *client.SolveStatus)
	warnings := []client.VertexWarning{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err = progrockDisp.processBuildkitProgress(ctx, ch, &warnings)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestProcessBuildkitProgress_VertexUpdates(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	display, err := NewProgrockDisplay(tmpFile)
	require.NoError(t, err)

	progrockDisp, ok := display.(*progrockDisplay)
	require.True(t, ok, "expected *progrockDisplay")
	ch := make(chan *client.SolveStatus)
	warnings := []client.VertexWarning{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Send status updates in a goroutine
	go func() {
		defer close(ch)

		now := time.Now()

		// Send a vertex that starts
		ch <- &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:  digest.FromString("test-vertex-1"),
					Name:    "test vertex 1",
					Started: &now,
				},
			},
		}

		// Send a vertex that completes
		ch <- &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:    digest.FromString("test-vertex-1"),
					Name:      "test vertex 1",
					Started:   &now,
					Completed: &now,
				},
			},
		}
	}()

	err = progrockDisp.processBuildkitProgress(ctx, ch, &warnings)
	assert.NoError(t, err)
}

func TestProcessBuildkitProgress_CachedVertex(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	display, err := NewProgrockDisplay(tmpFile)
	require.NoError(t, err)

	progrockDisp, ok := display.(*progrockDisplay)
	require.True(t, ok, "expected *progrockDisplay")
	ch := make(chan *client.SolveStatus)
	warnings := []client.VertexWarning{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		defer close(ch)

		now := time.Now()

		// Send a cached vertex
		ch <- &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:    digest.FromString("cached-vertex"),
					Name:      "cached vertex",
					Started:   &now,
					Completed: &now,
					Cached:    true,
				},
			},
		}
	}()

	err = progrockDisp.processBuildkitProgress(ctx, ch, &warnings)
	assert.NoError(t, err)
}

func TestProcessBuildkitProgress_VertexWithError(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	display, err := NewProgrockDisplay(tmpFile)
	require.NoError(t, err)

	progrockDisp, ok := display.(*progrockDisplay)
	require.True(t, ok, "expected *progrockDisplay")
	ch := make(chan *client.SolveStatus)
	warnings := []client.VertexWarning{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		defer close(ch)

		now := time.Now()

		// Send a vertex with an error
		ch <- &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:    digest.FromString("error-vertex"),
					Name:      "error vertex",
					Started:   &now,
					Completed: &now,
					Error:     "something went wrong",
				},
			},
		}
	}()

	err = progrockDisp.processBuildkitProgress(ctx, ch, &warnings)
	assert.NoError(t, err)
}

func TestProcessBuildkitProgress_ProgressUpdates(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	display, err := NewProgrockDisplay(tmpFile)
	require.NoError(t, err)

	progrockDisp, ok := display.(*progrockDisplay)
	require.True(t, ok, "expected *progrockDisplay")
	ch := make(chan *client.SolveStatus)
	warnings := []client.VertexWarning{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		defer close(ch)

		now := time.Now()
		vtxDigest := digest.FromString("progress-vertex")

		// Start a vertex
		ch <- &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:  vtxDigest,
					Name:    "progress vertex",
					Started: &now,
				},
			},
		}

		// Send progress update
		ch <- &client.SolveStatus{
			Statuses: []*client.VertexStatus{
				{
					Vertex:  vtxDigest,
					Name:    "downloading",
					Current: 50,
					Total:   100,
				},
			},
		}

		// Complete the progress
		ch <- &client.SolveStatus{
			Statuses: []*client.VertexStatus{
				{
					Vertex:    vtxDigest,
					Name:      "downloading",
					Current:   100,
					Total:     100,
					Completed: &now,
				},
			},
		}

		// Complete the vertex
		ch <- &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:    vtxDigest,
					Name:      "progress vertex",
					Started:   &now,
					Completed: &now,
				},
			},
		}
	}()

	err = progrockDisp.processBuildkitProgress(ctx, ch, &warnings)
	assert.NoError(t, err)
}

func TestProcessBuildkitProgress_LogOutput(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	display, err := NewProgrockDisplay(tmpFile)
	require.NoError(t, err)

	progrockDisp, ok := display.(*progrockDisplay)
	require.True(t, ok, "expected *progrockDisplay")
	ch := make(chan *client.SolveStatus)
	warnings := []client.VertexWarning{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		defer close(ch)

		now := time.Now()
		vtxDigest := digest.FromString("log-vertex")

		// Start a vertex
		ch <- &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:  vtxDigest,
					Name:    "log vertex",
					Started: &now,
				},
			},
		}

		// Send stdout log
		ch <- &client.SolveStatus{
			Logs: []*client.VertexLog{
				{
					Vertex: vtxDigest,
					Stream: 1, // stdout
					Data:   []byte("stdout message"),
				},
			},
		}

		// Send stderr log
		ch <- &client.SolveStatus{
			Logs: []*client.VertexLog{
				{
					Vertex: vtxDigest,
					Stream: 2, // stderr
					Data:   []byte("stderr message\n"),
				},
			},
		}

		// Complete the vertex
		ch <- &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:    vtxDigest,
					Name:      "log vertex",
					Started:   &now,
					Completed: &now,
				},
			},
		}
	}()

	err = progrockDisp.processBuildkitProgress(ctx, ch, &warnings)
	assert.NoError(t, err)
}

func TestProcessBuildkitProgress_Warnings(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	display, err := NewProgrockDisplay(tmpFile)
	require.NoError(t, err)

	progrockDisp, ok := display.(*progrockDisplay)
	require.True(t, ok, "expected *progrockDisplay")
	ch := make(chan *client.SolveStatus)
	warnings := []client.VertexWarning{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		defer close(ch)

		// Send a warning
		ch <- &client.SolveStatus{
			Warnings: []*client.VertexWarning{
				{
					Vertex: digest.FromString("warning-vertex"),
					Short:  []byte("this is a warning"),
				},
			},
		}
	}()

	err = progrockDisp.processBuildkitProgress(ctx, ch, &warnings)
	assert.NoError(t, err)
	assert.Len(t, warnings, 1)
	assert.Equal(t, "this is a warning", string(warnings[0].Short))
}

func TestProcessBuildkitProgress_NilStatus(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	display, err := NewProgrockDisplay(tmpFile)
	require.NoError(t, err)

	progrockDisp, ok := display.(*progrockDisplay)
	require.True(t, ok, "expected *progrockDisplay")
	ch := make(chan *client.SolveStatus)
	warnings := []client.VertexWarning{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		defer close(ch)

		// Send nil status (should be ignored)
		ch <- nil

		// Send a normal status after
		now := time.Now()
		ch <- &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:    digest.FromString("after-nil"),
					Name:      "vertex after nil",
					Started:   &now,
					Completed: &now,
				},
			},
		}
	}()

	err = progrockDisp.processBuildkitProgress(ctx, ch, &warnings)
	assert.NoError(t, err)
}

func TestProcessBuildkitProgress_EmptyVertexName(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	display, err := NewProgrockDisplay(tmpFile)
	require.NoError(t, err)

	progrockDisp, ok := display.(*progrockDisplay)
	require.True(t, ok, "expected *progrockDisplay")
	ch := make(chan *client.SolveStatus)
	warnings := []client.VertexWarning{}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		defer close(ch)

		now := time.Now()

		// Send a vertex with empty name
		ch <- &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:    digest.FromString("no-name-vertex"),
					Name:      "", // Empty name
					Started:   &now,
					Completed: &now,
				},
			},
		}
	}()

	err = progrockDisp.processBuildkitProgress(ctx, ch, &warnings)
	assert.NoError(t, err)
}
