package helm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractImages(t *testing.T) {
	tests := []struct {
		name      string
		manifests string
		want      []ChartImage
		wantErr   bool
	}{
		{
			name:      "empty manifests",
			manifests: "",
			want:      []ChartImage{},
		},
		{
			name:      "only separator",
			manifests: "---",
			want:      []ChartImage{},
		},
		{
			name: "simple Deployment with one container",
			manifests: `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  template:
    spec:
      containers:
        - name: nginx
          image: docker.io/library/nginx:1.25.0
`,
			want: []ChartImage{{Repository: "docker.io/library/nginx", Tag: "1.25.0"}},
		},
		{
			name: "Deployment with init container",
			manifests: `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  template:
    spec:
      initContainers:
        - name: init-db
          image: busybox:1.36
      containers:
        - name: app
          image: docker.io/myapp:2.0.0
`,
			want: []ChartImage{
				{Repository: "busybox", Tag: "1.36"},
				{Repository: "docker.io/myapp", Tag: "2.0.0"},
			},
		},
		{
			name: "multiple documents",
			manifests: `
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx:1.25.0
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: node-agent
spec:
  template:
    spec:
      containers:
        - name: agent
          image: quay.io/prometheus/node-exporter:v1.7.0
`,
			want: []ChartImage{
				{Repository: "nginx", Tag: "1.25.0"},
				{Repository: "quay.io/prometheus/node-exporter", Tag: "v1.7.0"},
			},
		},
		{
			name: "bare Pod",
			manifests: `
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
    - name: app
      image: redis:7.0
`,
			want: []ChartImage{{Repository: "redis", Tag: "7.0"}},
		},
		{
			name: "CronJob",
			manifests: `
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: ghcr.io/org/backup-tool:v1.2.3
`,
			want: []ChartImage{{Repository: "ghcr.io/org/backup-tool", Tag: "v1.2.3"}},
		},
		{
			name: "StatefulSet",
			manifests: `
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
spec:
  template:
    spec:
      containers:
        - name: postgres
          image: postgres:15.2
`,
			want: []ChartImage{{Repository: "postgres", Tag: "15.2"}},
		},
		{
			name: "deduplicates identical images across documents",
			manifests: `
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - image: redis:7.0
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - image: redis:7.0
`,
			want: []ChartImage{{Repository: "redis", Tag: "7.0"}},
		},
		{
			name: "image without tag defaults to latest",
			manifests: `
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - image: nginx
`,
			want: []ChartImage{{Repository: "nginx", Tag: "latest"}},
		},
		{
			name: "non-workload resource is ignored",
			manifests: `
apiVersion: v1
kind: ConfigMap
metadata:
  name: config
data:
  key: value
`,
			want: []ChartImage{},
		},
		{
			name: "multiple containers in one pod",
			manifests: `
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: myapp:1.0
        - name: sidecar
          image: envoy:v1.28.0
`,
			want: []ChartImage{
				{Repository: "myapp", Tag: "1.0"},
				{Repository: "envoy", Tag: "v1.28.0"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractImages(tt.manifests)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.ElementsMatch(t, tt.want, got)
			}
		})
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		name     string
		imageRef string
		wantRepo string
		wantTag  string
	}{
		{
			name:     "image with tag",
			imageRef: "nginx:1.25.0",
			wantRepo: "nginx",
			wantTag:  "1.25.0",
		},
		{
			name:     "image without tag defaults to latest",
			imageRef: "nginx",
			wantRepo: "nginx",
			wantTag:  "latest",
		},
		{
			name:     "full reference with registry",
			imageRef: "docker.io/library/nginx:1.25.0",
			wantRepo: "docker.io/library/nginx",
			wantTag:  "1.25.0",
		},
		{
			name:     "quay.io reference",
			imageRef: "quay.io/prometheus/node-exporter:v1.7.0",
			wantRepo: "quay.io/prometheus/node-exporter",
			wantTag:  "v1.7.0",
		},
		{
			name:     "digest pinned image",
			imageRef: "nginx@sha256:abc123",
			wantRepo: "nginx",
			wantTag:  "latest",
		},
		{
			name:     "empty string returns empty",
			imageRef: "",
			wantRepo: "",
			wantTag:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, tag := parseImageRef(tt.imageRef)
			assert.Equal(t, tt.wantRepo, repo)
			assert.Equal(t, tt.wantTag, tag)
		})
	}
}
