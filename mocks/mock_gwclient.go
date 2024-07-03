package mocks

import (
	"context"

	"github.com/tonistiigi/fsutil/types"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/mock"
)

// Mock for gwclient.Client
type MockGWClient struct {
	mock.Mock
}

func (m *MockGWClient) ResolveSourceMetadata(ctx context.Context, op *pb.SourceOp, opt sourceresolver.Opt) (*sourceresolver.MetaResponse, error) {
	args := m.Called(ctx, op, opt)
	return args.Get(0).(*sourceresolver.MetaResponse), args.Error(1)
}

func (m *MockGWClient) Solve(ctx context.Context, req gwclient.SolveRequest) (*gwclient.Result, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*gwclient.Result), args.Error(1)
}

func (m *MockGWClient) ResolveImageConfig(ctx context.Context, ref string, opt sourceresolver.Opt) (string, digest.Digest, []byte, error) {
	args := m.Called(ctx, ref, opt)
	return args.String(0), args.Get(1).(digest.Digest), args.Get(2).([]byte), args.Error(3)
}

func (m *MockGWClient) BuildOpts() gwclient.BuildOpts {
	args := m.Called()
	return args.Get(0).(gwclient.BuildOpts)
}

func (m *MockGWClient) Inputs(ctx context.Context) (map[string]llb.State, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]llb.State), args.Error(1)
}

func (m *MockGWClient) NewContainer(ctx context.Context, req gwclient.NewContainerRequest) (gwclient.Container, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(gwclient.Container), args.Error(1)
}

func (m *MockGWClient) Warn(ctx context.Context, dgst digest.Digest, msg string, opts gwclient.WarnOpts) error {
	args := m.Called(ctx, dgst, msg, opts)
	return args.Get(0).(error)
}

// MockReference is a mock of the Reference interface
type MockReference struct {
	mock.Mock
}

func (m *MockReference) ReadFile(ctx context.Context, req gwclient.ReadRequest) ([]byte, error) {
	args := m.Called(ctx, req)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockReference) ToState() (llb.State, error) {
	args := m.Called()
	return args.Get(0).(llb.State), args.Error(1)
}

func (m *MockReference) Evaluate(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Get(0).(error)
}

func (m *MockReference) StatFile(ctx context.Context, req gwclient.StatRequest) (*types.Stat, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*types.Stat), args.Error(1)
}

func (m *MockReference) ReadDir(ctx context.Context, req gwclient.ReadDirRequest) ([]*types.Stat, error) {
	args := m.Called(ctx, req)
	return args.Get(0).([]*types.Stat), args.Error(1)
}
