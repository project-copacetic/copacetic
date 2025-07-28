package common

import (
	"context"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sync/errgroup"
)

func TestDisplayProgress(t *testing.T) {
	ctx := context.Background()
	eg, egCtx := errgroup.WithContext(ctx)
	buildChannel := make(chan *client.SolveStatus)

	// Start the display progress goroutine
	DisplayProgress(egCtx, eg, buildChannel)

	// Simulate some build status updates
	go func() {
		defer close(buildChannel)

		// Send a test status
		status := &client.SolveStatus{
			Vertexes: []*client.Vertex{
				{
					Digest:  "test-digest",
					Name:    "test-vertex",
					Started: &[]time.Time{time.Now()}[0],
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

	// Start the display progress goroutine
	DisplayProgress(egCtx, eg, buildChannel)

	// Cancel the context immediately
	cancel()
	close(buildChannel)

	// Wait for completion
	err := eg.Wait()
	if err != nil {
		assert.Contains(t, err.Error(), "context canceled")
	}
}
