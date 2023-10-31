package utils

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

const testLogPipeMsg = "Test LogPipe message"

func TestLogPipe(t *testing.T) {
	cmd := exec.Command("echo", testLogPipeMsg)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to get stdout pipe: %s", err)
		return
	}

	stdOutBuf := new(bytes.Buffer)
	log.StandardLogger().SetOutput(stdOutBuf)
	go LogPipe(stdout, log.InfoLevel)
	err = cmd.Run()
	if err != nil {
		t.Fatalf("Failed to run command: %s", err)
		return
	}

	expected := fmt.Sprintf("level=info msg=\"%s\"", testLogPipeMsg)
	start := time.Now()
	for stdOutBuf.Len() < len(expected) {
		if time.Since(start) > 10*time.Millisecond {
			t.Errorf("LogPipe() did not finish write within 10ms")
			return
		}
		// Wait for LogPipe to finish writing, should be on the order of ns
		time.Sleep(1 * time.Millisecond)
	}

	if !strings.Contains(stdOutBuf.String(), fmt.Sprintf("level=info msg=\"%s\"", testLogPipeMsg)) {
		t.Errorf("LogPipe() result: \"%s\", want: \"%s\"", stdOutBuf.String(), testLogPipeMsg)
		return
	}
}
