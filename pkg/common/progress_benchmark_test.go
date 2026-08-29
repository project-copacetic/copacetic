package common

import (
	"context"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	"github.com/opencontainers/go-digest"
)

func BenchmarkForwardProgressWithPrefixRepeatedDigests(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src := make(chan *client.SolveStatus)
	dst := make(chan *client.SolveStatus)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ForwardProgressWithPrefix(ctx, src, dst, "linux/amd64")
	}()

	status := repeatedDigestSolveStatus()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src <- status
		prefixed := <-dst
		if len(prefixed.Statuses) != len(status.Statuses) || len(prefixed.Logs) != len(status.Logs) {
			b.Fatalf("unexpected forwarded status sizes: statuses=%d logs=%d", len(prefixed.Statuses), len(prefixed.Logs))
		}
	}
	b.StopTimer()

	close(src)
	<-done
}

func repeatedDigestSolveStatus() *client.SolveStatus {
	now := time.Unix(1_700_000_000, 0)
	digests := []digest.Digest{
		digest.FromString("vertex-0"),
		digest.FromString("vertex-1"),
		digest.FromString("vertex-2"),
		digest.FromString("vertex-3"),
	}

	vertexes := make([]*client.Vertex, len(digests))
	for i, d := range digests {
		vertexes[i] = &client.Vertex{
			Digest:  d,
			Name:    forwardProgressTestVertexName,
			Started: &now,
		}
	}

	statuses := make([]*client.VertexStatus, 64)
	logs := make([]*client.VertexLog, 64)
	for i := range statuses {
		d := digests[i%len(digests)]
		statuses[i] = &client.VertexStatus{
			ID:        "status",
			Vertex:    d,
			Name:      "status",
			Total:     100,
			Current:   int64(i),
			Timestamp: now,
			Started:   &now,
		}
		logs[i] = &client.VertexLog{
			Vertex:    d,
			Stream:    1,
			Data:      []byte("repeated log data"),
			Timestamp: now,
		}
	}

	return &client.SolveStatus{
		Vertexes: vertexes,
		Statuses: statuses,
		Logs:     logs,
		Warnings: []*client.VertexWarning{
			{Vertex: digests[0], Short: []byte("warning")},
		},
	}
}
