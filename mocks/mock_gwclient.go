package mocks

import (
	"context"
	"fmt"

	"github.com/tonistiigi/fsutil/types"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/mock"
)

// Mock for gwclient.Client.
type MockGWClient struct {
	mock.Mock
}

func (m *MockGWClient) ResolveSourceMetadata(ctx context.Context, op *pb.SourceOp, opt sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
	args := m.Called(ctx, op, opt)

	metaResponse, ok := args.Get(0).(*sourceresolver.MetaResponse)
	if !ok {
		return nil, fmt.Errorf("type assertion to *sourceresolver.MetaResponse failed")
	}

	return metaResponse, args.Error(1)
}

//nolint:gocritic
func (m *MockGWClient) Solve(ctx context.Context, req gwclient.SolveRequest) (*gwclient.Result, error) {
	args := m.Called(ctx, req)

	result, ok := args.Get(0).(*gwclient.Result)
	if !ok {
		return nil, fmt.Errorf("type assertion to *gwclient.Result failed")
	}

	return result, args.Error(1)
}

func (m *MockGWClient) ResolveImageConfig(ctx context.Context, ref string, opt sourceresolver.Opt) (string, digest.Digest, []byte, error) {
	args := m.Called(ctx, ref, opt)

	digestResult, ok1 := args.Get(1).(digest.Digest)
	if !ok1 {
		return "", "", nil, fmt.Errorf("type assertion to digest.Digest failed")
	}

	byteResult, ok2 := args.Get(2).([]byte)
	if !ok2 {
		return "", "", nil, fmt.Errorf("type assertion to []byte failed")
	}

	return args.String(0), digestResult, byteResult, args.Error(3)
}

func (m *MockGWClient) BuildOpts() gwclient.BuildOpts {
	args := m.Called()

	buildOpts, ok := args.Get(0).(gwclient.BuildOpts)
	if !ok {
		panic("type assertion to gwclient.BuildOpts failed")
	}

	return buildOpts
}

func (m *MockGWClient) Inputs(ctx context.Context) (map[string]llb.State, error) {
	args := m.Called(ctx)

	stateMap, ok := args.Get(0).(map[string]llb.State)
	if !ok {
		return nil, fmt.Errorf("type assertion to map[string]llb.State failed")
	}

	return stateMap, args.Error(1)
}

//nolint:gocritic
func (m *MockGWClient) NewContainer(ctx context.Context, req gwclient.NewContainerRequest) (gwclient.Container, error) {
	args := m.Called(ctx, req)

	container, ok := args.Get(0).(gwclient.Container)
	if !ok {
		return nil, fmt.Errorf("type assertion to gwclient.Container failed")
	}

	return container, args.Error(1)
}

//nolint:gocritic
func (m *MockGWClient) Warn(ctx context.Context, dgst digest.Digest, msg string, opts gwclient.WarnOpts) error {
	args := m.Called(ctx, dgst, msg, opts)

	warnErr, ok := args.Get(0).(error)
	if !ok {
		return fmt.Errorf("type assertion to error failed")
	}

	return warnErr
}

// MockReference is a mock of the Reference interface.
type MockReference struct {
	mock.Mock
}

func (m *MockReference) ReadFile(ctx context.Context, req gwclient.ReadRequest) ([]byte, error) {
	args := m.Called(ctx, req)

	byteResult, ok := args.Get(0).([]byte)
	if !ok {
		return nil, fmt.Errorf("type assertion to []byte failed")
	}

	return byteResult, args.Error(1)
}

func (m *MockReference) ToState() (llb.State, error) {
	args := m.Called()

	state, ok := args.Get(0).(llb.State)
	if !ok {
		return state, fmt.Errorf("type assertion to llb.State failed")
	}

	return state, args.Error(1)
}

func (m *MockReference) Evaluate(ctx context.Context) error {
	args := m.Called(ctx)

	evalErr, ok := args.Get(0).(error)
	if !ok {
		return fmt.Errorf("type assertion to error failed")
	}

	return evalErr
}

func (m *MockReference) StatFile(ctx context.Context, req gwclient.StatRequest) (*types.Stat, error) {
	args := m.Called(ctx, req)

	typesStat, ok := args.Get(0).(*types.Stat)
	if !ok {
		return nil, fmt.Errorf("type assertion to types.Stat failed")
	}

	return typesStat, args.Error(1)
}

func (m *MockReference) ReadDir(ctx context.Context, req gwclient.ReadDirRequest) ([]*types.Stat, error) {
	args := m.Called(ctx, req)

	typesStat, ok := args.Get(0).([]*types.Stat)
	if !ok {
		return nil, fmt.Errorf("type assertion to types failed")
	}

	return typesStat, args.Error(1)
}
