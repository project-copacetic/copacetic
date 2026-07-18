package tui

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/moby/buildkit/client"
	"github.com/opencontainers/go-digest"
	"github.com/vito/progrock"
)

const (
	benchVertexCount       = 1500
	benchTasksPerVertex    = 8
	benchVertexBatchSize   = 100
	benchStatusBatchSize   = 250
	benchLogBatchSize      = 200
	benchWarningEveryN     = 100
	benchCompletedTaskName = "task-00"
)

func BenchmarkProcessBuildkitProgressTaskBookkeeping(b *testing.B) {
	events, wantWarnings := syntheticBuildkitProgressEvents(benchVertexCount, benchTasksPerVertex)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tape := progrock.NewTape()
		display := &progrockDisplay{
			tape: tape,
			rec:  progrock.NewRecorder(tape),
		}
		warnings := make([]client.VertexWarning, 0, wantWarnings)
		ch := make(chan *client.SolveStatus)

		go func() {
			defer close(ch)
			for _, event := range events {
				ch <- event
			}
		}()

		if err := display.processBuildkitProgress(context.Background(), ch, &warnings); err != nil {
			b.Fatal(err)
		}
		if got := len(warnings); got != wantWarnings {
			b.Fatalf("warnings length = %d, want %d", got, wantWarnings)
		}
		if err := display.rec.Close(); err != nil {
			b.Fatal(err)
		}
	}
}

func syntheticBuildkitProgressEvents(vertexCount, tasksPerVertex int) ([]*client.SolveStatus, int) {
	now := time.Unix(1_704_067_200, 0)
	vertices := make([]digest.Digest, vertexCount)
	for i := range vertices {
		vertices[i] = digest.FromString(fmt.Sprintf("benchmark vertex %05d", i))
	}
	taskNames := make([]string, tasksPerVertex)
	for i := range taskNames {
		taskNames[i] = fmt.Sprintf("task-%02d", i)
	}

	events := make([]*client.SolveStatus, 0, vertexCount/benchVertexBatchSize+vertexCount*tasksPerVertex/benchStatusBatchSize+vertexCount/benchLogBatchSize)

	for start := 0; start < vertexCount; start += benchVertexBatchSize {
		end := min(start+benchVertexBatchSize, vertexCount)
		vertexes := make([]*client.Vertex, 0, end-start)
		for i := start; i < end; i++ {
			vertexes = append(vertexes, &client.Vertex{
				Digest:  vertices[i],
				Name:    fmt.Sprintf("benchmark vertex %05d", i),
				Started: &now,
			})
		}
		events = append(events, &client.SolveStatus{Vertexes: vertexes})
	}

	statuses := make([]*client.VertexStatus, 0, benchStatusBatchSize)
	flushStatuses := func() {
		if len(statuses) == 0 {
			return
		}
		events = append(events, &client.SolveStatus{Statuses: statuses})
		statuses = make([]*client.VertexStatus, 0, benchStatusBatchSize)
	}
	for i, vtx := range vertices {
		for taskID, taskName := range taskNames {
			statuses = append(statuses, &client.VertexStatus{
				Vertex:  vtx,
				Name:    taskName,
				Current: int64((i + taskID) % 100),
				Total:   int64(100 + taskID),
			})
			if len(statuses) == benchStatusBatchSize {
				flushStatuses()
			}
		}
	}
	flushStatuses()

	// Complete one task on every vertex while leaving the rest active for vertex cleanup.
	for _, vtx := range vertices {
		statuses = append(statuses, &client.VertexStatus{
			Vertex:    vtx,
			Name:      benchCompletedTaskName,
			Current:   100,
			Total:     100,
			Completed: &now,
		})
		if len(statuses) == benchStatusBatchSize {
			flushStatuses()
		}
	}
	flushStatuses()

	logs := make([]*client.VertexLog, 0, benchLogBatchSize)
	flushLogs := func() {
		if len(logs) == 0 {
			return
		}
		events = append(events, &client.SolveStatus{Logs: logs})
		logs = make([]*client.VertexLog, 0, benchLogBatchSize)
	}
	for i, vtx := range vertices {
		logs = append(logs, &client.VertexLog{
			Vertex: vtx,
			Stream: 1,
			Data:   []byte(fmt.Sprintf("stdout log line %05d", i)),
		})
		if len(logs) == benchLogBatchSize {
			flushLogs()
		}
		logs = append(logs, &client.VertexLog{
			Vertex: vtx,
			Stream: 2,
			Data:   []byte(fmt.Sprintf("stderr log line %05d\n", i)),
		})
		if len(logs) == benchLogBatchSize {
			flushLogs()
		}
	}
	flushLogs()

	wantWarnings := 0
	warnings := make([]*client.VertexWarning, 0, vertexCount/benchWarningEveryN)
	for i, vtx := range vertices {
		if i%benchWarningEveryN != 0 {
			continue
		}
		warnings = append(warnings, &client.VertexWarning{
			Vertex: vtx,
			Short:  []byte(fmt.Sprintf("synthetic warning %05d", i)),
		})
		wantWarnings++
	}
	events = append(events, &client.SolveStatus{Warnings: warnings})

	for start := 0; start < vertexCount; start += benchVertexBatchSize {
		end := min(start+benchVertexBatchSize, vertexCount)
		vertexes := make([]*client.Vertex, 0, end-start)
		for i := start; i < end; i++ {
			vertexes = append(vertexes, &client.Vertex{
				Digest:    vertices[i],
				Name:      fmt.Sprintf("benchmark vertex %05d", i),
				Started:   &now,
				Completed: &now,
			})
		}
		events = append(events, &client.SolveStatus{Vertexes: vertexes})
	}

	return events, wantWarnings
}
