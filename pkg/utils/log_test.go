package utils

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

const testLogPipeMsg = "Test LogPipe message"

func TestLogPipe(t *testing.T) {
	stdOutBuf := new(bytes.Buffer)
	logger := log.StandardLogger()
	originalOutput := logger.Out
	logger.SetOutput(stdOutBuf)
	t.Cleanup(func() {
		logger.SetOutput(originalOutput)
	})

	reader, writer := io.Pipe()
	done := make(chan struct{})
	go func() {
		LogPipe(reader, log.InfoLevel)
		close(done)
	}()

	if _, err := fmt.Fprintln(writer, testLogPipeMsg); err != nil {
		t.Fatalf("Failed to write log message: %s", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Failed to close log writer: %s", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("LogPipe() did not finish reading from the closed pipe")
	}

	if !strings.Contains(stdOutBuf.String(), fmt.Sprintf("level=info msg=\"%s\"", testLogPipeMsg)) {
		t.Errorf("LogPipe() result: %q, want message %q", stdOutBuf.String(), testLogPipeMsg)
	}
}
