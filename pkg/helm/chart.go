package helm

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	log "github.com/sirupsen/logrus"
	helmaction "helm.sh/helm/v3/pkg/action"
	helmchart "helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	helmcli "helm.sh/helm/v3/pkg/cli"
	helmregistry "helm.sh/helm/v3/pkg/registry"
)

// DownloadChart downloads a Helm chart from the given repository at the specified version.
// It is a function variable to allow test injection without network access.
var DownloadChart = func(name, version, repository string) (*helmchart.Chart, error) {
	tmpDir, err := os.MkdirTemp("", "copa-helm-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir for chart download: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	settings := helmcli.New()

	registryClient, err := helmregistry.NewClient(
		helmregistry.ClientOptEnableCache(true),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Helm registry client: %w", err)
	}

	cfg := &helmaction.Configuration{
		RegistryClient: registryClient,
	}

	pull := helmaction.NewPullWithOpts(helmaction.WithConfig(cfg))
	pull.Settings = settings
	pull.Version = version
	pull.DestDir = tmpDir
	pull.Untar = false

	// For OCI repos, the full reference includes the chart name.
	// For HTTP repos, we set RepoURL separately.
	var chartRef string
	if strings.HasPrefix(repository, "oci://") {
		chartRef = strings.TrimSuffix(repository, "/") + "/" + name
	} else {
		pull.RepoURL = repository
		chartRef = name
	}

	output, err := pull.Run(chartRef)
	if err != nil {
		return nil, fmt.Errorf("failed to pull chart '%s' v%s from %s: %w", name, version, repository, err)
	}
	if output != "" {
		log.Debugf("helm pull output for '%s': %s", name, output)
	}

	// Locate the downloaded .tgz file in the temp dir
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read temp dir after chart pull: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no chart archive found after pulling '%s'", name)
	}

	chartPath, err := findChartArchivePath(tmpDir, name)
	if err != nil {
		return nil, err
	}
	ch, err := loader.Load(chartPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load chart archive '%s': %w", chartPath, err)
	}

	return ch, nil
}

func findChartArchivePath(tmpDir, name string) (string, error) {
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return "", fmt.Errorf("failed to read temp dir after chart pull: %w", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".tgz") {
			return tmpDir + "/" + entry.Name(), nil
		}
	}
	return "", fmt.Errorf("no chart archive found after pulling '%s'", name)
}

// RenderChart renders a Helm chart to Kubernetes manifests using default values.
// It is a function variable to allow test injection.
var RenderChart = func(ch *helmchart.Chart) (string, error) {
	settings := helmcli.New()
	cfg := &helmaction.Configuration{}
	// Initialize with no-op debug log to suppress Helm's internal logging
	if err := cfg.Init(settings.RESTClientGetter(), "default", "memory", func(_ string, _ ...interface{}) {}); err != nil {
		// If Init fails (no kubeconfig in test/CI), we still continue since ClientOnly mode
		// does not require a real cluster connection. Log and proceed.
		log.Debugf("helm: cfg.Init failed (expected in no-cluster environments): %v", err)
	}

	install := helmaction.NewInstall(cfg)
	install.DryRun = true
	install.ClientOnly = true
	install.Replace = true
	install.ReleaseName = ch.Metadata.Name
	install.Namespace = "default"
	install.IncludeCRDs = true
	// Use the Kubernetes version matching our k8s.io/apimachinery dependency so
	// charts with a high kubeVersion constraint (e.g. >=1.25.0) don't fail.
	// ClientOnly mode defaults to v1.20.0 via chartutil.DefaultCapabilities.
	install.KubeVersion = kubeVersionFromBuildDeps()

	release, err := install.Run(ch, map[string]interface{}{})
	if err != nil {
		return "", fmt.Errorf("failed to render chart '%s': %w", ch.Metadata.Name, err)
	}

	return release.Manifest, nil
}

// kubeVersionFromBuildDeps derives the Kubernetes version from the k8s.io/apimachinery
// module version embedded in the binary's build info.
// k8s.io/apimachinery follows the convention v0.{MINOR}.{PATCH} = K8s 1.{MINOR}.{PATCH}.
// Falls back to v1.32.0 if build info is unavailable or the module is not found.
func kubeVersionFromBuildDeps() *chartutil.KubeVersion {
	const fallbackVersion = "v1.32.0"
	const fallbackMinor = "32"

	info, ok := debug.ReadBuildInfo()
	if !ok {
		log.Debugf("helm: build info unavailable, using fallback KubeVersion %s", fallbackVersion)
		return &chartutil.KubeVersion{Version: fallbackVersion, Major: "1", Minor: fallbackMinor}
	}

	for _, dep := range info.Deps {
		if dep.Path != "k8s.io/apimachinery" {
			continue
		}
		v := dep.Version // e.g. "v0.35.1"
		rest, ok := strings.CutPrefix(v, "v0.")
		if !ok {
			break
		}
		parts := strings.SplitN(rest, ".", 2)
		if len(parts) != 2 {
			break
		}
		minor, patch := parts[0], parts[1]
		kubeVer := fmt.Sprintf("v1.%s.%s", minor, patch)
		log.Debugf("helm: derived KubeVersion %s from k8s.io/apimachinery %s", kubeVer, v)
		return &chartutil.KubeVersion{Version: kubeVer, Major: "1", Minor: minor}
	}

	log.Debugf("helm: k8s.io/apimachinery not found in build deps, using fallback KubeVersion %s", fallbackVersion)
	return &chartutil.KubeVersion{Version: fallbackVersion, Major: "1", Minor: fallbackMinor}
}

// DiscoverChartImages downloads, renders, and extracts all container images
// from a Helm chart. Overrides are applied to the discovered images.
// This is the primary entry point for chart-based image discovery.
func DiscoverChartImages(ch *helmchart.Chart, overrides map[string]OverrideSpec) ([]ChartImage, error) {
	rendered, err := RenderChart(ch)
	if err != nil {
		return nil, fmt.Errorf("failed to render chart '%s': %w", ch.Metadata.Name, err)
	}

	images, err := ExtractImages(rendered)
	if err != nil {
		return nil, fmt.Errorf("failed to extract images from chart '%s': %w", ch.Metadata.Name, err)
	}

	if len(images) == 0 {
		log.Warnf("helm: no container images found in chart '%s' — chart may be CRD-only or have all images in conditionally-disabled templates", ch.Metadata.Name)
		return images, nil
	}

	return ApplyOverrides(images, overrides), nil
}
