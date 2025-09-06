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

	"github.com/hashicorp/go-multierror"
	"github.com/project-copacetic/copacetic/pkg/patch"
	"github.com/project-copacetic/copacetic/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// patchJobStatus represents the status of a single image patching job.
type patchJobStatus struct {
	Name   string
	Source string
	Target string
	Status string
	Error  error
}

// PatchFromConfig orchestrates the bulk patching process based on a configuration file.
func PatchFromConfig(ctx context.Context, configPath string, opts *types.Options) error {
	yamlFile, err := os.ReadFile(configPath)
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

	numWorkers := runtime.NumCPU()

	// Initialize a worker pool with a number of workers equal to the number of CPUs.
	log.Debugf("initializing worker pool with %d concurrent workers.", numWorkers)

	var wg sync.WaitGroup
	var mu sync.Mutex

	jobsChan := make(chan job, len(jobsToRun))
	errChan := make(chan error, len(jobsToRun))
	results := make([]patchJobStatus, 0, len(jobsToRun))

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
				// Resolve the target tag for the patched image.
				targetTag, err := resolveTargetTag(spec.Target, tag)
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

				log.Debugf("[Worker %d] --> Starting patch for %s", workerID, imageWithTag)

				jobOpts := *opts // Shallow copy of the global options
				jobOpts.Image = imageWithTag
				jobOpts.PatchedTag = targetTag
				jobOpts.Platforms = spec.Platforms
				jobOpts.Suffix = ""

				// Execute the patch operation.
				err = patch.Patch(ctx, &jobOpts)
				mu.Lock()
				jobResult := patchJobStatus{
					Name:   spec.Name,
					Source: imageWithTag,
					Target: targetTag,
				}
				if err != nil {
					jobResult.Status = "Failed"
					jobResult.Error = err
					errChan <- err
					log.Errorf("Failed to patch %s: %v", imageWithTag, err)
				} else {
					jobResult.Status = "Patched"
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
		}
		row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", res.Name, res.Status, res.Source, res.Target, details)
		fmt.Fprintln(writer, row)
	}

	// Flush the writer to ensure all content is written to the buffer.
	writer.Flush()
	log.Infof("\n\nBulk Patch Summary:\n%s", buf.String())
}
