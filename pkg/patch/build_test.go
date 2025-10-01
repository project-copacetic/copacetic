package patch

import (
	"testing"

	sourcepolicy "github.com/moby/buildkit/sourcepolicy/pb"
	"github.com/stretchr/testify/assert"
)

// TestValidateSourcePolicy tests the validateSourcePolicy function.
func TestValidateSourcePolicy(t *testing.T) {
	testCases := []struct {
		name        string
		policy      *sourcepolicy.Policy
		wantErr     bool
		errContains string
	}{
		{
			name:    "nil policy",
			policy:  nil,
			wantErr: false,
		},
		{
			name: "empty rules",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{},
			},
			wantErr: false,
		},
		{
			name: "supported identifier - ubuntu",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/library/ubuntu:20.04",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "supported identifier - alpine",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/library/alpine:3.14",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "supported identifier - centos",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/library/centos:7",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unsupported identifier - redhat",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "registry.redhat.io/rhel8/rhel:latest",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "RedHat is not supported via source policies",
		},
		{
			name: "unsupported identifier - rockylinux",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/library/rockylinux:8",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "RockyLinux is not supported via source policies",
		},
		{
			name: "unsupported identifier - alma",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/library/almalinux:8",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "AlmaLinux is not supported via source policies",
		},
		{
			name: "case sensitive - REDHAT (should not match)",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "docker.io/REDHAT/rhel:8",
						},
					},
				},
			},
			wantErr: false, // strings.Contains is case-sensitive, so "REDHAT" != "redhat"
		},
		{
			name: "partial match - contains redhat in path",
			policy: &sourcepolicy.Policy{
				Rules: []*sourcepolicy.Rule{
					{
						Updates: &sourcepolicy.Update{
							Identifier: "quay.io/redhat/some-image:latest",
						},
					},
				},
			},
			wantErr:     true,
			errContains: "RedHat is not supported via source policies",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSourcePolicy(tc.policy)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
