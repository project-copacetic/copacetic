package testenv

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/moby/buildkit/client"
	digest "github.com/opencontainers/go-digest"
)

const (
	// buildLogTailLines is how many trailing output lines are reported per step.
	buildLogTailLines = 40
	// buildLogMaxBytes bounds the output kept per step while a build runs.
	buildLogMaxBytes = 64 << 10
)

// buildLog collects the output of each BuildKit step so that a failing test can
// show what the step printed (for example, a package manager's error) rather
// than only the step's exit code.
type buildLog struct {
	mu    sync.Mutex
	order []digest.Digest
	steps map[digest.Digest]*stepLog
}

type stepLog struct {
	name   string
	err    string
	output []byte
}

func newBuildLog() *buildLog {
	return &buildLog{steps: map[digest.Digest]*stepLog{}}
}

func (b *buildLog) step(d digest.Digest) *stepLog {
	s, ok := b.steps[d]
	if !ok {
		s = &stepLog{}
		b.steps[d] = s
		b.order = append(b.order, d)
	}
	return s
}

// consume records status updates until ch is closed.
func (b *buildLog) consume(ch <-chan *client.SolveStatus) {
	for status := range ch {
		b.add(status)
	}
}

func (b *buildLog) add(status *client.SolveStatus) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, v := range status.Vertexes {
		s := b.step(v.Digest)
		if v.Name != "" {
			s.name = v.Name
		}
		if v.Error != "" {
			s.err = v.Error
		}
	}
	for _, l := range status.Logs {
		s := b.step(l.Vertex)
		s.output = append(s.output, l.Data...)
		if excess := len(s.output) - buildLogMaxBytes; excess > 0 {
			s.output = s.output[excess:]
		}
	}
}

// String returns the trailing output of every step that printed something or
// failed, in the order the steps first appeared.
func (b *buildLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var sb strings.Builder
	for _, d := range b.order {
		s := b.steps[d]
		output := bytes.TrimRight(s.output, "\n")
		if len(output) == 0 && s.err == "" {
			continue
		}
		fmt.Fprintf(&sb, "--- %s\n", s.name)
		if s.err != "" {
			fmt.Fprintf(&sb, "error: %s\n", s.err)
		}
		if len(output) == 0 {
			continue
		}
		lines := strings.Split(string(output), "\n")
		if len(lines) > buildLogTailLines {
			sb.WriteString("[... earlier output omitted]\n")
			lines = lines[len(lines)-buildLogTailLines:]
		}
		sb.WriteString(strings.Join(lines, "\n"))
		sb.WriteString("\n")
	}
	return sb.String()
}
