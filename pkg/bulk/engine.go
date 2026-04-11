package bulk

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"text/template"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/go-multierror"
	"github.com/project-copacetic/copacetic/pkg/helm"
	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	helmchart "helm.sh/helm/v3/pkg/chart"
)

// patchJobStatus represents the status of a single image patching job.
type patchJobStatus struct {
	Name    string
	Source  string
	Target  string
	Status  string
	Error   error
	Details string
}

// chartResolution holds a downloaded Helm chart alongside its discovered images.
type chartResolution struct {
	Spec   ChartSpec
	Chart  *helmchart.Chart
	Images []helm.ChartImage
}

// ChartImageMapping tracks the original→patched image mapping for chart-based patching.
type ChartImageMapping struct {
	ChartName    string
	OriginalRepo string
	OriginalTag  string
	PatchedRepo  string
	PatchedTag   string
}

// mergeTarget merges top-level target configuration with image-level target.
// Image-level settings take precedence over top-level defaults.
func mergeTarget(globalTarget, imageTarget TargetSpec) TargetSpec {
	result := globalTarget // Start with global defaults

	// Override with image-level settings if provided
	if imageTarget.Registry != "" {
		result.Registry = imageTarget.Registry
	}
	if imageTarget.Tag != "" {
		result.Tag = imageTarget.Tag
	}

	return result
}

// buildTargetRepository constructs the target repository path by combining
// the target registry with the image name (last path segment) from the source image.
//
// Note: Only the last path segment is preserved. Images with the same name but
// different namespaces (e.g., "team-a/redis" and "team-b/redis") would both map
// to "<target>/redis". Use per-image target overrides in the config to avoid collisions.
//
// Examples:
//   - sourceImage: "quay.io/opstree/redis", targetRegistry: "ghcr.io/myorg" → "ghcr.io/myorg/redis"
//   - sourceImage: "docker.io/library/nginx", targetRegistry: "ghcr.io/myorg" → "ghcr.io/myorg/nginx"
//   - sourceImage: "redis", targetRegistry: "ghcr.io/myorg" → "ghcr.io/myorg/redis"
func buildTargetRepository(sourceImage, targetRegistry string) (string, error) {
	if targetRegistry == "" {
		return sourceImage, nil
	}

	// Parse the source image to extract the image name
	ref, err := name.ParseReference(sourceImage)
	if err != nil {
		return "", fmt.Errorf("failed to parse source image '%s': %w", sourceImage, err)
	}

	// Extract the image name (last segment of the repository path)
	repoStr := ref.Context().RepositoryStr()
	repoParts := strings.Split(repoStr, "/")
	imageName := repoParts[len(repoParts)-1]

	// Combine target registry with image name
	return fmt.Sprintf("%s/%s", strings.TrimSuffix(targetRegistry, "/"), imageName), nil
}

func resolveChartImagesWithCharts(ctx context.Context, charts []ChartSpec, overrides map[string]OverrideSpec) ([]ImageSpec, []chartResolution, error) {
	_ = ctx
	var allImages []helm.ChartImage
	var resolutions []chartResolution
	var errs *multierror.Error

	for _, chartSpec := range charts {
		log.Infof("Downloading Helm chart '%s' v%s from %s...", chartSpec.Name, chartSpec.Version, chartSpec.Repository)
		ch, err := helm.DownloadChart(chartSpec.Name, chartSpec.Version, chartSpec.Repository)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("chart '%s': %w", chartSpec.Name, err))
			continue
		}

		helmOverrides := toHelmOverrides(overrides)
		images, err := helm.DiscoverChartImages(ch, helmOverrides)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("chart '%s': %w", chartSpec.Name, err))
			continue
		}

		log.Infof("Found %d image(s) in chart '%s'", len(images), chartSpec.Name)
		allImages = append(allImages, images...)
		resolutions = append(resolutions, chartResolution{
			Spec:   chartSpec,
			Chart:  ch,
			Images: images,
		})
	}

	if errs.ErrorOrNil() != nil {
		log.Warnf("Encountered errors resolving chart images:\n%s", errs.Error())
	}

	return chartImagesToSpecs(allImages), resolutions, errs.ErrorOrNil()
}

func toHelmOverrides(overrides map[string]OverrideSpec) map[string]helm.OverrideSpec {
	if overrides == nil {
		return nil
	}
	result := make(map[string]helm.OverrideSpec, len(overrides))
	for k, v := range overrides {
		result[k] = helm.OverrideSpec{From: v.From, To: v.To}
	}
	return result
}

func chartImagesToSpecs(images []helm.ChartImage) []ImageSpec {
	specs := make([]ImageSpec, 0, len(images))
	for _, img := range images {
		specs = append(specs, ImageSpec{
			Name:  img.Repository,
			Image: img.Repository,
			Tags: TagStrategy{
				Strategy: StrategyList,
				List:     []string{img.Tag},
			},
		})
	}
	return specs
}

func mergeImageSpecs(config PatchConfig, chartImages []ImageSpec) PatchConfig {
	explicitRefs := make(map[string]struct{}, len(config.Images))
	for _, img := range config.Images {
		explicitRefs[img.Image] = struct{}{}
	}

	merged := make([]ImageSpec, len(config.Images))
	copy(merged, config.Images)

	for _, chartImg := range chartImages {
		if _, exists := explicitRefs[chartImg.Image]; exists {
			log.Debugf("Skipping chart-discovered image '%s': overridden by explicit image spec", chartImg.Image)
			continue
		}
		merged = append(merged, chartImg)
		explicitRefs[chartImg.Image] = struct{}{}
	}

	return PatchConfig{
		APIVersion:  config.APIVersion,
		Kind:        config.Kind,
		Target:      config.Target,
		ChartTarget: config.ChartTarget,
		Charts:      config.Charts,
		Overrides:   config.Overrides,
		Images:      merged,
	}
}

func filterMappingsForChart(res chartResolution, mappings []ChartImageMapping) []ChartImageMapping {
	type repoTag struct{ repo, tag string }
	chartImages := make(map[repoTag]bool)
	for _, img := range res.Images {
		chartImages[repoTag{repo: img.Repository, tag: img.Tag}] = true
	}

	var filtered []ChartImageMapping
	for _, m := range mappings {
		if chartImages[repoTag{repo: m.OriginalRepo, tag: m.OriginalTag}] {
			filtered = append(filtered, m)
			continue
		}
		for _, img := range res.Images {
			if m.OriginalTag == img.Tag &&
				(helm.MatchRepositoryPattern(m.OriginalRepo, img.Repository) || helm.MatchRepositoryPattern(img.Repository, m.OriginalRepo)) {
				filtered = append(filtered, m)
				break
			}
		}
	}
	return filtered
}

func toHelmImageMappings(mappings []ChartImageMapping) []helm.ImageMapping {
	result := make([]helm.ImageMapping, len(mappings))
	for i, m := range mappings {
		result[i] = helm.ImageMapping{
			OriginalRepo: m.OriginalRepo,
			OriginalTag:  m.OriginalTag,
			PatchedRepo:  m.PatchedRepo,
			PatchedTag:   m.PatchedTag,
		}
	}
	return result
}

func generateAndPushPatchedCharts(resolutions []chartResolution, mappings []ChartImageMapping, config PatchConfig) error {
	if config.ChartTarget == nil || config.ChartTarget.Registry == "" {
		return nil
	}

	explicitPaths := make(map[string]string)
	for key, o := range config.Overrides {
		if o.ValuePath != "" {
			explicitPaths[key] = o.ValuePath
		}
	}

	var errs *multierror.Error

	for _, res := range resolutions {
		chartMappings := filterMappingsForChart(res, mappings)
		if len(chartMappings) == 0 {
			log.Infof("No successfully patched images for chart '%s', skipping chart generation", res.Spec.Name)
			continue
		}

		valuePaths := helm.ResolveImageValuePaths(res.Chart.Values, res.Images, explicitPaths)
		if len(valuePaths) == 0 {
			log.Warnf("No value paths detected for chart '%s' — auto-detection failed for all images. Skipping chart generation. Use overrides.valuePath to specify paths manually.", res.Spec.Name)
			continue
		}

		helmMappings := toHelmImageMappings(chartMappings)
		spec := helm.ChartSourceSpec{
			Name:       res.Spec.Name,
			Version:    res.Spec.Version,
			Repository: res.Spec.Repository,
		}
		patchedChart, err := helm.BuildPatchedChart(res.Chart, spec, helmMappings, valuePaths)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("chart '%s': failed to build patched chart: %w", res.Spec.Name, err))
			continue
		}

		ociRef := fmt.Sprintf("%s/%s:%s",
			strings.TrimSuffix(config.ChartTarget.Registry, "/"),
			patchedChart.Name(),
			patchedChart.Metadata.Version,
		)

		log.Infof("Packaging and pushing patched chart '%s' to %s...", patchedChart.Name(), ociRef)
		result, err := helm.PackageAndPush(patchedChart, ociRef)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("chart '%s': failed to push: %w", res.Spec.Name, err))
			continue
		}

		log.Infof("Successfully pushed patched chart '%s' → %s", patchedChart.Name(), result.Ref)
	}

	return errs.ErrorOrNil()
}

// PatchFromConfig orchestrates the bulk patching process based on a configuration file.
func PatchFromConfig(ctx context.Context, configPath string, opts *types.Options) error {
	yamlFile, err := os.ReadFile(configPath) // #nosec G304 - configPath is provided by user via CLI flag
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	var config PatchConfig
	if err := yaml.Unmarshal(yamlFile, &config); err != nil {
		return fmt.Errorf("failed to parse YAML from %s: %w", configPath, err)
	}

	if config.APIVersion != ExpectedAPIVersion {
		return fmt.Errorf("invalid apiVersion: expected '%s', but got '%s'", ExpectedAPIVersion, config.APIVersion)
	}
	if config.Kind != ExpectedKind {
		return fmt.Errorf("invalid kind: expected '%s', but got '%s'", ExpectedKind, config.Kind)
	}

	if len(config.Charts) == 0 && len(config.Images) == 0 {
		return fmt.Errorf("config must specify at least one chart or image")
	}

	if err := validateCharts(config.Charts); err != nil {
		return fmt.Errorf("invalid chart config: %w", err)
	}
	if err := validateOverrides(config.Overrides); err != nil {
		return fmt.Errorf("invalid overrides config: %w", err)
	}
	if err := validateChartTarget(config.ChartTarget); err != nil {
		return fmt.Errorf("invalid chart target config: %w", err)
	}
	if opts.ChartRegistry != "" && config.ChartTarget == nil {
		config.ChartTarget = &ChartTargetSpec{Registry: opts.ChartRegistry}
		if err := validateChartTarget(config.ChartTarget); err != nil {
			return fmt.Errorf("invalid --chart-registry flag: %w", err)
		}
	}

	var chartResolutions []chartResolution
	if len(config.Charts) > 0 {
		var chartImages []ImageSpec
		chartImages, chartResolutions, err = resolveChartImagesWithCharts(ctx, config.Charts, config.Overrides)
		if err != nil {
			return fmt.Errorf("failed to resolve chart images: %w", err)
		}
		config = mergeImageSpecs(config, chartImages)
	}

	log.Debug("Discovering all tags to calculate total job count...")
	type job struct {
		spec *ImageSpec
		tag  string
	}
	var jobsToRun []job
	var discoveryErrors *multierror.Error

	for i := range config.Images {
		imageSpec := &config.Images[i]
		tagsToPatch, err := FindTagsToPatch(imageSpec)
		if err != nil {
			discoveryErrors = multierror.Append(discoveryErrors, fmt.Errorf("error discovering tags for '%s': %w", imageSpec.Name, err))
			continue
		}
		for _, tag := range tagsToPatch {
			jobsToRun = append(jobsToRun, job{spec: imageSpec, tag: tag})
		}
	}

	if discoveryErrors.ErrorOrNil() != nil {
		log.Warnf("Encountered errors during tag discovery phase:\n%s", discoveryErrors.Error())
	}

	if len(jobsToRun) == 0 {
		log.Warn("No tags found to patch across all image specs.")
		return nil
	}

	log.Debugf("Total number of patch jobs to execute: %d", len(jobsToRun))

	// Build report index once before workers start
	var reports *reportIndex
	if opts.Report != "" {
		reports = buildReportIndex(opts.Report)
	}

	numWorkers := runtime.NumCPU()

	// Initialize a worker pool with a number of workers equal to the number of CPUs.
	log.Debugf("initializing worker pool with %d concurrent workers.", numWorkers)

	var wg sync.WaitGroup
	var mu sync.Mutex

	jobsChan := make(chan job, len(jobsToRun))
	errChan := make(chan error, len(jobsToRun))
	results := make([]patchJobStatus, 0, len(jobsToRun))
	var imageMappings []ChartImageMapping

	log.Infof("Starting bulk patch for %d image(s) defined in %s...", len(config.Images), configPath)

	// Start worker goroutines.
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for j := range jobsChan {
				spec := j.spec
				tag := j.tag
				imageWithTag := fmt.Sprintf("%s:%s", spec.Image, tag)

				// Merge global target config with image-level target config
				effectiveTarget := mergeTarget(config.Target, spec.Target)

				// Build the target repository (registry + image name)
				targetRepo, err := buildTargetRepository(spec.Image, effectiveTarget.Registry)
				if err != nil {
					errMessage := fmt.Errorf("worker %d: error building target repository for '%s': %w", workerID, spec.Name, err)
					mu.Lock()
					results = append(results, patchJobStatus{
						Name:   spec.Name,
						Source: imageWithTag,
						Target: "N/A",
						Status: "Error",
						Error:  errMessage,
					})
					mu.Unlock()
					errChan <- errMessage
					continue
				}

				// Resolve the target tag for the patched image.
				targetTag, err := resolveTargetTag(effectiveTarget, tag)
				if err != nil {
					errMessage := fmt.Errorf("worker %d: error resolving target tag for '%s:%s': %w", workerID, spec.Name, tag, err)
					mu.Lock()
					results = append(results, patchJobStatus{
						Name:   spec.Name,
						Source: imageWithTag,
						Target: "N/A",
						Status: "Error",
						Error:  errMessage,
					})
					mu.Unlock()
					errChan <- errMessage
					continue
				}

				// Evaluate whether patching is needed and resolve the final tag
				// Use targetRepo for skip detection (queries the registry where patched images are pushed)
				action := evaluatePatchAction(targetRepo, targetTag, opts.Scanner, reports, opts.PkgTypes, opts.LibraryPatchLevel)
				if action.ShouldSkip {
					// Record as skipped
					mu.Lock()
					results = append(results, patchJobStatus{
						Name:    spec.Name,
						Source:  imageWithTag,
						Target:  fmt.Sprintf("%s:%s", targetRepo, action.ResolvedTag),
						Status:  "Skipped",
						Details: action.Reason,
					})
					mu.Unlock()
					log.Debugf("[Worker %d] --> Skipping patch for %s: %s", workerID, imageWithTag, action.Reason)
					continue
				}

				// Use the resolved tag (may be version-bumped)
				finalTag := action.ResolvedTag
				if finalTag == "" {
					finalTag = targetTag
				}

				log.Debugf("[Worker %d] --> Starting patch for %s with tag %s", workerID, imageWithTag, finalTag)

				// Build the full patched image reference using target repository
				patchedImageRef := fmt.Sprintf("%s:%s", targetRepo, finalTag)

				jobOpts := *opts // Shallow copy of the global options
				jobOpts.Image = imageWithTag
				jobOpts.PatchedTag = patchedImageRef
				jobOpts.Platforms = spec.Platforms
				jobOpts.Suffix = ""

				// Execute the patch operation.
				err = patch.Patch(ctx, &jobOpts)
				mu.Lock()
				jobResult := patchJobStatus{
					Name:   spec.Name,
					Source: imageWithTag,
					Target: patchedImageRef,
				}
				if err != nil {
					jobResult.Status = "Failed"
					jobResult.Error = err
					errChan <- err
					log.Errorf("Failed to patch %s: %v", imageWithTag, err)
				} else {
					jobResult.Status = "Patched"
					imageMappings = append(imageMappings, ChartImageMapping{
						ChartName:    spec.Name,
						OriginalRepo: spec.Image,
						OriginalTag:  tag,
						PatchedRepo:  targetRepo,
						PatchedTag:   finalTag,
					})
				}
				results = append(results, jobResult)
				mu.Unlock()
			}
		}(w)
	}

	// Distribute jobs to the workers.
	log.Info("Distributing jobs to workers...")
	for _, j := range jobsToRun {
		jobsChan <- j
	}
	close(jobsChan)

	// Wait for all workers to complete.
	wg.Wait()
	close(errChan)

	var multiErr *multierror.Error
	for err := range errChan {
		multiErr = multierror.Append(multiErr, err)
	}

	// Sort results for consistent output.
	sort.Slice(results, func(i, j int) bool {
		if results[i].Name != results[j].Name {
			return results[i].Name < results[j].Name
		}
		return results[i].Source < results[j].Source
	})

	// Print a summary of all patch jobs.
	printSummary(results)

	if config.ChartTarget != nil && len(chartResolutions) > 0 {
		if err := generateAndPushPatchedCharts(chartResolutions, imageMappings, config); err != nil {
			log.Errorf("Failed to generate/push patched charts: %v", err)
			multiErr = multierror.Append(multiErr, err)
		}
	}

	if opts.IgnoreError {
		return nil
	}
	return multiErr.ErrorOrNil()
}

// resolveTargetTag resolves the target tag for a patched image based on the provided TargetSpec and the source tag.
func resolveTargetTag(target TargetSpec, sourceTag string) (string, error) {
	tagTemplate := "{{ .SourceTag }}-patched"
	// Use custom target tag if provided in the config.
	if target.Tag != "" {
		tagTemplate = target.Tag
	}

	tmpl, err := template.New("tag").Parse(tagTemplate)
	if err != nil {
		return "", fmt.Errorf("invalid target tag template: %w", err)
	}

	// Execute the template to generate the target tag.
	data := struct{ SourceTag string }{SourceTag: sourceTag}
	var builder strings.Builder
	if err := tmpl.Execute(&builder, data); err != nil {
		return "", fmt.Errorf("failed to execute tag template: %w", err)
	}

	return builder.String(), nil
}

// printSummary prints a formatted summary table of all patch jobs.
func printSummary(results []patchJobStatus) {
	if len(results) == 0 {
		// No results to print.
		return
	}

	var buf bytes.Buffer
	writer := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	// Write table header.
	fmt.Fprintln(writer, "NAME\tSTATUS\tSOURCE IMAGE\tPATCHED TAG\tDETAILS")

	for _, res := range results {
		details := "OK"
		if res.Error != nil {
			details = res.Error.Error()
		} else if res.Details != "" {
			details = res.Details
		}
		row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", res.Name, res.Status, res.Source, res.Target, details)
		fmt.Fprintln(writer, row)
	}

	// Flush the writer to ensure all content is written to the buffer.
	if err := writer.Flush(); err != nil {
		log.Warnf("Failed to flush summary table writer: %v", err)
	}
	log.Infof("\n\nBulk Patch Summary:\n%s", buf.String())
}
