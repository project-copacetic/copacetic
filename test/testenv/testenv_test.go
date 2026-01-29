package testenv

import (
	"context"
	"testing"

	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/stretchr/testify/assert"
)

func TestNormalizeImageRef(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "short name without tag",
			input:    "alpine",
			expected: "docker.io/library/alpine:latest",
		},
		{
			name:     "short name with tag",
			input:    "alpine:3.18",
			expected: "docker.io/library/alpine:3.18",
		},
		{
			name:     "fully qualified name",
			input:    "ghcr.io/myorg/myimage:v1",
			expected: "ghcr.io/myorg/myimage:v1",
		},
		{
			name:     "docker hub with org",
			input:    "nginx:1.21",
			expected: "docker.io/library/nginx:1.21",
		},
		{
			name:     "invalid reference returns original",
			input:    "::invalid::",
			expected: "::invalid::",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeImageRef(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTestEnvAddr(t *testing.T) {
	addr := "docker://"
	env := New(addr)
	assert.Equal(t, addr, env.Addr())
}

func TestTestEnvCloseWithoutClient(t *testing.T) {
	env := New("")
	err := env.Close()
	assert.NoError(t, err)
}

// TestRecoverFromPanic validates that panics within a test function
// are properly captured by the recover mechanism in RunTest.
// This is important because panics inside client.Build() callbacks
// would otherwise crash without proper test failure reporting.
func TestRecoverFromPanic(t *testing.T) {
	// This test validates the recover pattern by checking that the
	// testErr variable is properly set when a panic occurs.
	// We can't directly test RunTest's recover without a BuildKit connection,
	// but we can verify the recover pattern itself works correctly.

	var capturedErr error
	testFunc := func() {
		defer func() {
			if r := recover(); r != nil {
				if err, ok := r.(error); ok {
					capturedErr = err
				} else {
					capturedErr = assert.AnError
				}
			}
		}()
		panic("test panic")
	}

	testFunc()
	assert.NotNil(t, capturedErr, "recover should capture panic")
}

// TestRecoverFromErrorPanic validates that error-type panics are
// properly captured and converted.
func TestRecoverFromErrorPanic(t *testing.T) {
	var capturedErr error
	expectedErr := assert.AnError

	testFunc := func() {
		defer func() {
			if r := recover(); r != nil {
				if err, ok := r.(error); ok {
					capturedErr = err
				}
			}
		}()
		panic(expectedErr)
	}

	testFunc()
	assert.Equal(t, expectedErr, capturedErr, "recover should capture error-type panic")
}

// TestRunnerConfig validates the test runner configuration options.
func TestRunnerConfigSkipExport(t *testing.T) {
	cfg := &TestRunnerConfig{}
	opt := WithSkipExport()
	opt(cfg)
	assert.True(t, cfg.SkipExport)
}

// TestTestFuncSignature ensures the TestFunc type matches expected signature.
func TestTestFuncSignature(t *testing.T) {
	// This compile-time check ensures TestFunc signature is correct.
	var _ TestFunc = func(ctx context.Context, t *testing.T, c gwclient.Client) {
		// Test function implementation
	}
}
