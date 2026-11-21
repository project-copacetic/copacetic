package testenv

import (
	"fmt"
	"strings"
	"testing"

	"github.com/moby/buildkit/client"
	digest "github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
)

func TestBuildLog(t *testing.T) {
	failed, quiet, chatty := digest.FromString("failed"), digest.FromString("quiet"), digest.FromString("chatty")

	var many strings.Builder
	for i := range buildLogTailLines + 5 {
		fmt.Fprintf(&many, "line %d\n", i)
	}

	ch := make(chan *client.SolveStatus, 4)
	ch <- &client.SolveStatus{Vertexes: []*client.Vertex{
		{Digest: failed, Name: "[1/2] dnf upgrade"},
		{Digest: quiet, Name: "resolve image"},
		{Digest: chatty, Name: "[2/2] rpm -qa"},
	}}
	ch <- &client.SolveStatus{Logs: []*client.VertexLog{
		{Vertex: failed, Data: []byte("Curl error (23): Failed writing received data\n")},
		{Vertex: chatty, Data: []byte(many.String())},
	}}
	ch <- &client.SolveStatus{Vertexes: []*client.Vertex{
		{Digest: failed, Name: "[1/2] dnf upgrade", Error: "exit code: 1"},
	}}
	close(ch)

	logs := newBuildLog()
	logs.consume(ch)
	out := logs.String()

	assert.Contains(t, out, "--- [1/2] dnf upgrade\nerror: exit code: 1\nCurl error (23): Failed writing received data\n")
	assert.NotContains(t, out, "resolve image", "steps without output or errors are omitted")
	assert.Contains(t, out, "--- [2/2] rpm -qa\n[... earlier output omitted]\nline 5\n")
	assert.NotContains(t, out, "\nline 4\n")
	assert.True(t, strings.HasSuffix(out, fmt.Sprintf("line %d\n", buildLogTailLines+4)))
	assert.Less(t, strings.Index(out, "dnf upgrade"), strings.Index(out, "rpm -qa"), "steps keep their order")
}

func TestBuildLogBoundsOutput(t *testing.T) {
	d := digest.FromString("big")
	logs := newBuildLog()
	logs.add(&client.SolveStatus{Logs: []*client.VertexLog{{Vertex: d, Data: make([]byte, buildLogMaxBytes)}}})
	logs.add(&client.SolveStatus{Logs: []*client.VertexLog{{Vertex: d, Data: []byte("tail")}}})
	assert.Len(t, logs.steps[d].output, buildLogMaxBytes)
	assert.True(t, strings.HasSuffix(string(logs.steps[d].output), "tail"))
}
