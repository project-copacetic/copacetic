package helm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// PackageAndPushFunc is replaceable in tests.
var PackageAndPushFunc = packageAndPush

// PackageAndPush delegates to the configured chart publisher.
func PackageAndPush(ctx context.Context, ch *Chart, ociRef string) (string, error) {
	return PackageAndPushFunc(ctx, ch, ociRef)
}

func packageAndPush(ctx context.Context, ch *Chart, ociRef string) (string, error) {
	tmpDir, err := os.MkdirTemp("", "copa-chart-push-*")
	if err != nil {
		return "", fmt.Errorf("create chart package directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	chartDir := filepath.Join(tmpDir, ch.Metadata.Name)
	if err := writeChartDirectory(chartDir, ch); err != nil {
		return "", err
	}
	if _, err := RunHelm(ctx, "package", chartDir, "--destination", tmpDir); err != nil {
		return "", fmt.Errorf("package chart %q: %w", ch.Metadata.Name, err)
	}
	archivePath, err := findChartArchivePath(tmpDir, ch.Metadata.Name)
	if err != nil {
		return "", err
	}
	destination, ok := strings.CutSuffix(ociRef, "/"+ch.Metadata.Name+":"+ch.Metadata.Version)
	if !ok {
		return "", fmt.Errorf("chart reference %q does not match chart %s:%s", ociRef, ch.Metadata.Name, ch.Metadata.Version)
	}
	if _, err := RunHelm(ctx, "push", archivePath, destination); err != nil {
		return "", fmt.Errorf("push chart to %s: %w", ociRef, err)
	}
	return ociRef, nil
}

func writeChartDirectory(dir string, ch *Chart) error {
	if err := os.MkdirAll(filepath.Join(dir, "charts"), 0o700); err != nil {
		return fmt.Errorf("create wrapper chart directory: %w", err)
	}
	metadata, err := yaml.Marshal(ch.Metadata)
	if err != nil {
		return fmt.Errorf("marshal wrapper Chart.yaml: %w", err)
	}
	values, err := yaml.Marshal(ch.Values)
	if err != nil {
		return fmt.Errorf("marshal wrapper values.yaml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Chart.yaml"), metadata, 0o600); err != nil {
		return fmt.Errorf("write wrapper Chart.yaml: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "values.yaml"), values, 0o600); err != nil {
		return fmt.Errorf("write wrapper values.yaml: %w", err)
	}
	dependency := filepath.Join(dir, "charts", ch.Metadata.Dependencies[0].Name+"-"+ch.Metadata.Dependencies[0].Version+".tgz")
	if err := os.WriteFile(dependency, ch.Archive, 0o600); err != nil {
		return fmt.Errorf("write embedded chart dependency: %w", err)
	}
	return nil
}
