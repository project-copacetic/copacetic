package helm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestApplyOverrides(t *testing.T) {
	tests := []struct {
		name      string
		images    []ChartImage
		overrides map[string]OverrideSpec
		want      []ChartImage
	}{
		{
			name:      "nil overrides returns original images unchanged",
			images:    []ChartImage{{Repository: "docker.io/timberio/vector", Tag: "0.53.0-distroless-libc"}},
			overrides: nil,
			want:      []ChartImage{{Repository: "docker.io/timberio/vector", Tag: "0.53.0-distroless-libc"}},
		},
		{
			name:      "empty overrides returns original images unchanged",
			images:    []ChartImage{{Repository: "docker.io/timberio/vector", Tag: "0.53.0-distroless-libc"}},
			overrides: map[string]OverrideSpec{},
			want:      []ChartImage{{Repository: "docker.io/timberio/vector", Tag: "0.53.0-distroless-libc"}},
		},
		{
			name:   "exact key match applies override",
			images: []ChartImage{{Repository: "timberio/vector", Tag: "0.53.0-distroless-libc"}},
			overrides: map[string]OverrideSpec{
				"timberio/vector": {From: "distroless-libc", To: "debian"},
			},
			want: []ChartImage{{Repository: "timberio/vector", Tag: "0.53.0-debian"}},
		},
		{
			name:   "suffix match with registry prefix",
			images: []ChartImage{{Repository: "docker.io/timberio/vector", Tag: "0.53.0-distroless-libc"}},
			overrides: map[string]OverrideSpec{
				"timberio/vector": {From: "distroless-libc", To: "debian"},
			},
			want: []ChartImage{{Repository: "docker.io/timberio/vector", Tag: "0.53.0-debian"}},
		},
		{
			name:   "from substring not in tag leaves tag unchanged",
			images: []ChartImage{{Repository: "docker.io/timberio/vector", Tag: "0.53.0-debian"}},
			overrides: map[string]OverrideSpec{
				"timberio/vector": {From: "distroless-libc", To: "debian"},
			},
			want: []ChartImage{{Repository: "docker.io/timberio/vector", Tag: "0.53.0-debian"}},
		},
		{
			name:   "no matching override passes image through",
			images: []ChartImage{{Repository: "docker.io/nginx", Tag: "1.25.0"}},
			overrides: map[string]OverrideSpec{
				"timberio/vector": {From: "distroless-libc", To: "debian"},
			},
			want: []ChartImage{{Repository: "docker.io/nginx", Tag: "1.25.0"}},
		},
		{
			name: "multiple overrides applied to different images",
			images: []ChartImage{
				{Repository: "docker.io/timberio/vector", Tag: "0.53.0-distroless-libc"},
				{Repository: "docker.io/prometheus/prometheus", Tag: "v2.50.0"},
				{Repository: "quay.io/foo/bar", Tag: "1.0.0-alpine"},
			},
			overrides: map[string]OverrideSpec{
				"timberio/vector": {From: "distroless-libc", To: "debian"},
				"foo/bar":         {From: "alpine", To: "debian"},
			},
			want: []ChartImage{
				{Repository: "docker.io/timberio/vector", Tag: "0.53.0-debian"},
				{Repository: "docker.io/prometheus/prometheus", Tag: "v2.50.0"},
				{Repository: "quay.io/foo/bar", Tag: "1.0.0-debian"},
			},
		},
		{
			name:      "empty images returns empty slice",
			images:    []ChartImage{},
			overrides: map[string]OverrideSpec{"timberio/vector": {From: "a", To: "b"}},
			want:      []ChartImage{},
		},
		{
			name:      "nil images returns nil",
			images:    nil,
			overrides: map[string]OverrideSpec{"timberio/vector": {From: "a", To: "b"}},
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ApplyOverrides(tt.images, tt.overrides)
			assert.Equal(t, tt.want, got)

			// Immutability check: original slice must not be modified
			if len(tt.images) > 0 && len(tt.overrides) > 0 {
				originalFirst := tt.images[0]
				_ = ApplyOverrides(tt.images, tt.overrides)
				assert.Equal(t, originalFirst, tt.images[0], "ApplyOverrides must not mutate input")
			}
		})
	}
}

func TestMatchOverride(t *testing.T) {
	overrides := map[string]OverrideSpec{
		"timberio/vector":       {From: "distroless-libc", To: "debian"},
		"prometheus/prometheus": {From: "old", To: "new"},
	}

	tests := []struct {
		name       string
		repository string
		wantFound  bool
		wantKey    string
	}{
		{
			name:       "exact key match",
			repository: "timberio/vector",
			wantFound:  true,
			wantKey:    "timberio/vector",
		},
		{
			name:       "match with docker.io prefix",
			repository: "docker.io/timberio/vector",
			wantFound:  true,
			wantKey:    "timberio/vector",
		},
		{
			name:       "match with ghcr.io prefix",
			repository: "ghcr.io/timberio/vector",
			wantFound:  true,
			wantKey:    "timberio/vector",
		},
		{
			name:       "no match",
			repository: "docker.io/nginx",
			wantFound:  false,
		},
		{
			name:       "partial name should not match (security: avoid prefix attacks)",
			repository: "malicious/timberio/vector",
			wantFound:  true, // suffix "timberio/vector" does match
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, found := matchOverride(tt.repository, overrides)
			assert.Equal(t, tt.wantFound, found)
		})
	}
}
