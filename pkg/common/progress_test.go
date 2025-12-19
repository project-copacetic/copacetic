package common

import (
	"context"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/util/progress/progressui"
	"github.com/opencontainers/go-digest"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
)

func TestDisplayProgress(t *testing.T) {
	ctx := context.Background()
	eg, egCtx := errgroup.WithContext(ctx)
	buildChannel := make(chan *client.SolveStatus)
	progress := progressui.AutoMode

	// Start the display progress goroutine
	DisplayProgress(egCtx, eg, buildChannel, progress)

	// Simulate some build status updates
	go func() {
		defer close(buildChannel)

		// Send a test status
		now := time.Now()
		status := &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:  digest.FromString("test-vertex"),
					Name:    "test-vertex",
					Started: &now,
				},
			},
		}

		select {
		case buildChannel <- status:
		case <-egCtx.Done():
			return
		}

		// Give some time for processing
		time.Sleep(100 * time.Millisecond)
	}()

	// Wait for completion with timeout
	done := make(chan error)
	go func() {
		done <- eg.Wait()
	}()

	select {
	case err := <-done:
		// Progress display might fail in test environment without TTY
		// We accept both success and specific TTY-related errors
		if err != nil {
			assert.Contains(t, err.Error(), "not a terminal")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Test timed out")
	}
}

func TestDisplayProgress_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	eg, egCtx := errgroup.WithContext(ctx)
	buildChannel := make(chan *client.SolveStatus)
	progress := progressui.AutoMode

	// Start the display progress goroutine
	DisplayProgress(egCtx, eg, buildChannel, progress)

	// Cancel the context immediately
	cancel()
	close(buildChannel)

	// Wait for completion
	err := eg.Wait()
	if err != nil {
		assert.Contains(t, err.Error(), "context canceled")
	}
}

func TestDisplayProgressQuiet(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eg, ctx := errgroup.WithContext(ctx)
	ch := make(chan *client.SolveStatus)

	// Start progress display in quiet mode
	DisplayProgress(ctx, eg, ch, progressui.QuietMode)

	// Send some status updates
	now := time.Now()
	ch <- &client.SolveStatus{
		Vertexes: []*client.Vertex{
			{
				Digest:    digest.FromString("test"),
				Name:      "test vertex",
				Started:   &now,
				Completed: &now,
			},
		},
	}

	// Close the channel
	close(ch)

	// Wait for completion
	err := eg.Wait()
	assert.NoError(t, err)
}

func TestDisplayProgressPlain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eg, ctx := errgroup.WithContext(ctx)
	ch := make(chan *client.SolveStatus)

	// Start progress display in plain mode
	DisplayProgress(ctx, eg, ch, progressui.PlainMode)

	// Send some status updates
	now := time.Now()
	ch <- &client.SolveStatus{
		Vertexes: []*client.Vertex{
			{
				Digest:    digest.FromString("test"),
				Name:      "test vertex",
				Started:   &now,
				Completed: &now,
			},
		},
	}

	// Close the channel
	close(ch)

	// Wait for completion
	err := eg.Wait()
	assert.NoError(t, err)
}

func TestDisplayProgressWithDebugMode(t *testing.T) {
	// Save and restore log level
	originalLevel := log.GetLevel()
	defer log.SetLevel(originalLevel)

	// Set debug level
	log.SetLevel(log.DebugLevel)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eg, ctx := errgroup.WithContext(ctx)
	ch := make(chan *client.SolveStatus)

	// Start progress display - should use plain mode due to debug
	DisplayProgress(ctx, eg, ch, progressui.AutoMode)

	// Close the channel immediately
	close(ch)

	// Wait for completion
	err := eg.Wait()
	assert.NoError(t, err)
}
