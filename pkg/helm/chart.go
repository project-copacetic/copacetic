package helm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Chart is the local representation needed for discovery and wrapper generation.
type Chart struct {
	Metadata Metadata
	Values   map[string]interface{}
	Archive  []byte
}

// Metadata is the chart metadata Copa needs.
type Metadata struct {
	APIVersion   string            `yaml:"apiVersion"`
	Name         string            `yaml:"name"`
	Version      string            `yaml:"version"`
	Description  string            `yaml:"description,omitempty"`
	Type         string            `yaml:"type,omitempty"`
	Annotations  map[string]string `yaml:"annotations,omitempty"`
	Dependencies []Dependency      `yaml:"dependencies,omitempty"`
}

// Dependency describes a wrapper chart dependency.
type Dependency struct {
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Repository string `yaml:"repository"`
}

// DownloadChart downloads and reads a chart archive with the Helm CLI.
var DownloadChart = func(ctx context.Context, name, version, repository string) (*Chart, error) {
	tmpDir, err := os.MkdirTemp("", "copa-helm-pull-*")
	if err != nil {
		return nil, fmt.Errorf("create chart download directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	args := []string{"pull", "--destination", tmpDir, "--version", version}
	if strings.HasPrefix(repository, "oci://") {
		args = append(args, strings.TrimSuffix(repository, "/")+"/"+name)
	} else {
		args = append(args, name, "--repo", repository)
	}
	if _, err := RunHelm(ctx, args...); err != nil {
		return nil, fmt.Errorf("pull chart %q v%s from %s: %w", name, version, repository, err)
	}
	archivePath, err := findChartArchivePath(tmpDir, name)
	if err != nil {
		return nil, err
	}
	archive, err := os.ReadFile(archivePath) // #nosec G304 -- controlled temporary directory
	if err != nil {
		return nil, fmt.Errorf("read downloaded chart archive: %w", err)
	}
	return loadChart(archive)
}

func findChartArchivePath(dir, name string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read chart download directory: %w", err)
	}
	prefix := name + "-"
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".tgz") {
			return filepath.Join(dir, entry.Name()), nil
		}
	}
	return "", fmt.Errorf("no chart archive found after pulling %q", name)
}

func loadChart(archive []byte) (*Chart, error) {
	files, err := chartFiles(archive)
	if err != nil {
		return nil, err
	}
	chartYAML, ok := files["Chart.yaml"]
	if !ok {
		return nil, fmt.Errorf("chart archive has no Chart.yaml")
	}
	var metadata Metadata
	if err := yaml.Unmarshal(chartYAML, &metadata); err != nil {
		return nil, fmt.Errorf("parse Chart.yaml: %w", err)
	}
	if metadata.Name == "" || metadata.Version == "" {
		return nil, fmt.Errorf("chart.yaml must contain name and version")
	}
	values := map[string]interface{}{}
	if valuesYAML, ok := files["values.yaml"]; ok {
		if err := yaml.Unmarshal(valuesYAML, &values); err != nil {
			return nil, fmt.Errorf("parse values.yaml: %w", err)
		}
	}
	return &Chart{Metadata: metadata, Values: values, Archive: archive}, nil
}

func chartFiles(archive []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("open chart archive: %w", err)
	}
	defer gz.Close()

	files := make(map[string][]byte)
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read chart archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		parts := strings.SplitN(filepath.ToSlash(header.Name), "/", 2)
		if len(parts) != 2 || parts[1] == "" || filepath.IsAbs(parts[1]) || strings.HasPrefix(parts[1], "../") {
			return nil, fmt.Errorf("unsafe chart archive path %q", header.Name)
		}
		data, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil {
			return nil, fmt.Errorf("read chart archive file %q: %w", header.Name, err)
		}
		if int64(len(data)) > header.Size {
			return nil, fmt.Errorf("chart archive file %q exceeds declared size", header.Name)
		}
		files[parts[1]] = data
	}
	return files, nil
}

// RenderChart renders default chart values, including CRDs and hooks, with the Helm CLI.
var RenderChart = func(ctx context.Context, ch *Chart) (string, error) {
	tmpDir, err := os.MkdirTemp("", "copa-helm-template-*")
	if err != nil {
		return "", fmt.Errorf("create chart render directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	archivePath := filepath.Join(tmpDir, ch.Metadata.Name+".tgz")
	if err := os.WriteFile(archivePath, ch.Archive, 0o600); err != nil {
		return "", fmt.Errorf("write chart archive for rendering: %w", err)
	}
	output, err := RunHelm(ctx, "template", ch.Metadata.Name, archivePath, "--include-crds")
	if err != nil {
		return "", fmt.Errorf("render chart %q: %w", ch.Metadata.Name, err)
	}
	return string(output), nil
}

// DiscoverChartImages renders and extracts all container images from a chart.
func DiscoverChartImages(ctx context.Context, ch *Chart, overrides map[string]OverrideSpec) ([]ChartImage, error) {
	rendered, err := RenderChart(ctx, ch)
	if err != nil {
		return nil, err
	}
	images, err := ExtractImages(rendered)
	if err != nil {
		return nil, fmt.Errorf("extract images from chart %q: %w", ch.Metadata.Name, err)
	}
	return ApplyOverrides(images, overrides), nil
}
