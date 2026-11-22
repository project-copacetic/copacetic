package patch

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/project-copacetic/copacetic/pkg/types"
)

// stubPatchShutdown replaces the patch run and shutdown timings for one test.
// Tests that use it change package variables, so they must not call t.Parallel.
func stubPatchShutdown(t *testing.T, run func(context.Context, *types.Options) error, grace time.Duration) {
	t.Helper()
	origRun, origGrace, origNotice := runPatch, shutdownGracePeriod, shutdownNoticeDelay
	runPatch = run
	shutdownGracePeriod = grace
	shutdownNoticeDelay = 10 * time.Millisecond
	t.Cleanup(func() {
		runPatch, shutdownGracePeriod, shutdownNoticeDelay = origRun, origGrace, origNotice
	})
}

// slowCleanupPatch blocks until its context ends, then takes cleanupTime to run
// its deferred cleanup, as removing a large working folder or staging directory can.
func slowCleanupPatch(cleaned *atomic.Bool, cleanupTime time.Duration) func(context.Context, *types.Options) error {
	return func(ctx context.Context, _ *types.Options) error {
		defer func() {
			time.Sleep(cleanupTime)
			cleaned.Store(true)
		}()
		<-ctx.Done()
		return ctx.Err()
	}
}

func TestPatchWaitsForCleanupAfterShutdown(t *testing.T) {
	// The cleanup takes longer than the one second Patch used to wait.
	const cleanupTime = 1500 * time.Millisecond

	tests := []struct {
		name    string
		timeout time.Duration
		cancel  bool
		check   func(t *testing.T, err error)
	}{
		{
			name:    "timeout",
			timeout: 50 * time.Millisecond,
			check: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "patch exceeded timeout")
			},
		},
		{
			name:    "cancel",
			timeout: time.Minute,
			cancel:  true,
			check: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, context.Canceled)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cleaned atomic.Bool
			stubPatchShutdown(t, slowCleanupPatch(&cleaned, cleanupTime), 10*time.Second)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				time.AfterFunc(50*time.Millisecond, cancel)
			}

			err := Patch(ctx, &types.Options{Timeout: tt.timeout, Progress: "quiet"})

			tt.check(t, err)
			assert.True(t, cleaned.Load(), "Patch returned before the patch's deferred cleanup ran")
		})
	}
}

func TestPatchReportsResultThatArrivesAfterDeadline(t *testing.T) {
	tests := []struct {
		name    string
		result  error
		wantErr func(t *testing.T, err error)
	}{
		{
			name: "success",
			wantErr: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name:   "no updates found",
			result: types.ErrNoUpdatesFound,
			wantErr: func(t *testing.T, err error) {
				assert.ErrorIs(t, err, types.ErrNoUpdatesFound)
			},
		},
		{
			name:   "error caused by the cancellation",
			result: errors.New("rpc error: code = Canceled desc = context canceled"),
			wantErr: func(t *testing.T, err error) {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "patch exceeded timeout")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The patch returns its result only after the deadline has passed.
			stubPatchShutdown(t, func(ctx context.Context, _ *types.Options) error {
				<-ctx.Done()
				return tt.result
			}, 10*time.Second)

			err := Patch(context.Background(), &types.Options{Timeout: 50 * time.Millisecond, Progress: "quiet"})

			tt.wantErr(t, err)
		})
	}
}

func TestPatchShutdownWaitIsBounded(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	// This patch ignores cancellation until the test ends.
	stubPatchShutdown(t, func(context.Context, *types.Options) error {
		<-release
		return errors.New("released")
	}, 200*time.Millisecond)

	start := time.Now()
	err := Patch(context.Background(), &types.Options{Timeout: 50 * time.Millisecond, Progress: "quiet"})
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "patch exceeded timeout")
	assert.Less(t, elapsed, 5*time.Second, "Patch must stop waiting after the grace period")
	assert.GreaterOrEqual(t, elapsed, 200*time.Millisecond, "Patch should wait for the grace period")
}
