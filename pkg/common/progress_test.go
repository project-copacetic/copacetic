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

const forwardProgressTestVertexName = "vertex"

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

func TestForwardProgressWithPrefixRemapsRepeatedDigestsWithoutMutatingInput(t *testing.T) {
	ctx := context.Background()
	src := make(chan *client.SolveStatus)
	dst := make(chan *client.SolveStatus)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardProgressWithPrefix(ctx, src, dst, "linux/arm64")
	}()

	now := time.Unix(1_700_000_001, 0)
	vertexA := digest.FromString("vertex-a")
	vertexB := digest.FromString("vertex-b")
	status := &client.SolveStatus{
		Vertexes: []*client.Vertex{
			{Digest: vertexA, Name: "install packages", Started: &now},
			{Digest: vertexB, Name: "copy files", Completed: &now},
		},
		Statuses: []*client.VertexStatus{
			{ID: "status-a-1", Vertex: vertexA, Name: "download", Timestamp: now},
			{ID: "status-a-2", Vertex: vertexA, Name: "extract", Timestamp: now},
			{ID: "status-b", Vertex: vertexB, Name: "copy", Timestamp: now},
		},
		Logs: []*client.VertexLog{
			{Vertex: vertexA, Stream: 1, Data: []byte("log a"), Timestamp: now},
			{Vertex: vertexA, Stream: 2, Data: []byte("log a again"), Timestamp: now},
			{Vertex: vertexB, Stream: 1, Data: []byte("log b"), Timestamp: now},
		},
		Warnings: []*client.VertexWarning{
			{Vertex: vertexA, Short: []byte("warning")},
		},
	}

	src <- status
	prefixed := <-dst
	close(src)
	<-done

	remappedA := digest.FromString("linux/arm64:" + vertexA.String())
	remappedB := digest.FromString("linux/arm64:" + vertexB.String())

	assert.Equal(t, remappedA, prefixed.Vertexes[0].Digest)
	assert.Equal(t, "[linux/arm64] install packages", prefixed.Vertexes[0].Name)
	assert.Equal(t, remappedB, prefixed.Vertexes[1].Digest)
	assert.Equal(t, "[linux/arm64] copy files", prefixed.Vertexes[1].Name)

	assert.Equal(t, remappedA, prefixed.Statuses[0].Vertex)
	assert.Equal(t, remappedA, prefixed.Statuses[1].Vertex)
	assert.Equal(t, remappedB, prefixed.Statuses[2].Vertex)
	assert.Equal(t, remappedA, prefixed.Logs[0].Vertex)
	assert.Equal(t, remappedA, prefixed.Logs[1].Vertex)
	assert.Equal(t, remappedB, prefixed.Logs[2].Vertex)

	// Warnings are forwarded unchanged, matching the previous behavior.
	assert.Equal(t, vertexA, prefixed.Warnings[0].Vertex)

	// The input status and nested vertex/status/log fields are not mutated.
	assert.Equal(t, vertexA, status.Vertexes[0].Digest)
	assert.Equal(t, "install packages", status.Vertexes[0].Name)
	assert.Equal(t, vertexB, status.Vertexes[1].Digest)
	assert.Equal(t, "copy files", status.Vertexes[1].Name)
	assert.Equal(t, vertexA, status.Statuses[0].Vertex)
	assert.Equal(t, vertexA, status.Statuses[1].Vertex)
	assert.Equal(t, vertexB, status.Statuses[2].Vertex)
	assert.Equal(t, vertexA, status.Logs[0].Vertex)
	assert.Equal(t, vertexA, status.Logs[1].Vertex)
	assert.Equal(t, vertexB, status.Logs[2].Vertex)
}

func TestForwardProgressWithPrefixSkipsNilStatus(t *testing.T) {
	ctx := context.Background()
	src := make(chan *client.SolveStatus)
	dst := make(chan *client.SolveStatus)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardProgressWithPrefix(ctx, src, dst, "target")
	}()

	vertex := digest.FromString("vertex")
	status := &client.SolveStatus{
		Vertexes: []*client.Vertex{{Digest: vertex, Name: forwardProgressTestVertexName}},
	}

	src <- nil
	src <- status
	prefixed := <-dst
	close(src)
	<-done

	assert.Len(t, prefixed.Vertexes, 1)
	assert.Equal(t, digest.FromString("target:"+vertex.String()), prefixed.Vertexes[0].Digest)
}

func TestForwardProgressWithPrefixReturnsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	src := make(chan *client.SolveStatus)
	dst := make(chan *client.SolveStatus)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardProgressWithPrefix(ctx, src, dst, "target")
	}()

	src <- &client.SolveStatus{
		Vertexes: []*client.Vertex{{Digest: digest.FromString(forwardProgressTestVertexName), Name: forwardProgressTestVertexName}},
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ForwardProgressWithPrefix did not return after context cancellation")
	}
}
