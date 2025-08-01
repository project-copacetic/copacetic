package bulk

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/patch"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type OrchestratorOptions struct {
	Timeout       string
	Push          bool
	IgnoreErrors  bool
	WorkingFolder string
	Scanner       string
	Format        string
	Output        string
	Loader        string
	BKOOpts       buildkit.Opts
}

type patchJobStatus struct {
	Name   string
	Source string
	Target string
	Status string
	Error  error
}

func PatchFromConfig(ctx context.Context, configPath string, opts *OrchestratorOptions) error {
	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	var config PatchConfig
	if err := yaml.Unmarshal(yamlFile, &config); err != nil {
		return fmt.Errorf("failed to parse YAML from %s: %w", configPath, err)
	}

	timeout, err := time.ParseDuration(opts.Timeout)
	if err != nil {
		return fmt.Errorf("invalid timeout duration: %w", err)
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
	log.Debugf("initializing worker pool with %d concurrent workers.", numWorkers)

	var wg sync.WaitGroup
	var mu sync.Mutex

	jobsChan := make(chan job, len(jobsToRun))
	errChan := make(chan error, len(jobsToRun))
	results := make([]patchJobStatus, 0, len(jobsToRun))

	log.Infof("Starting bulk patch for %d image(s) defined in %s...", len(config.Images), configPath)

	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for j := range jobsChan {
				spec := j.spec
				tag := j.tag
				imageWithTag := fmt.Sprintf("%s:%s", spec.Image, tag)
				targetTag, err := resolveTargetTag(spec.Target, tag)
				if err != nil {
					errChan <- fmt.Errorf("worker %d: error resolving target tag for '%s:%s': %w", workerID, spec.Name, tag, err)
					return
				}

				log.Debugf("[Worker %d] --> Starting patch for %s", workerID, imageWithTag)

				err = patch.Patch(ctx, timeout,
					imageWithTag,
					"", // reportPath is empty for update-all mode
					targetTag,
					"", // suffix is empty since we provide an explicit targetTag
					opts.WorkingFolder,
					opts.Scanner,
					opts.Format,
					opts.Output,
					opts.Loader,
					opts.IgnoreErrors,
					opts.Push,
					spec.Platforms,
					opts.BKOOpts,
				)
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

	log.Info("Distributing jobs to workers...")
	for _, j := range jobsToRun {
		jobsChan <- j
	}
	close(jobsChan)

	wg.Wait()
	close(errChan)

	var multiErr *multierror.Error
	for err := range errChan {
		multiErr = multierror.Append(multiErr, err)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Name != results[j].Name {
			return results[i].Name < results[j].Name
		}
		return results[i].Source < results[j].Source
	})

	printSummary(results)

	return multiErr.ErrorOrNil()
}

func resolveTargetTag(target TargetSpec, sourceTag string) (string, error) {
	tagTemplate := "{{ .SourceTag }}-patched"
	if target.Tag != "" {
		tagTemplate = target.Tag
	}

	tmpl, err := template.New("tag").Parse(tagTemplate)
	if err != nil {
		return "", fmt.Errorf("invalid target tag template: %w", err)
	}

	data := struct{ SourceTag string }{SourceTag: sourceTag}
	var builder strings.Builder
	if err := tmpl.Execute(&builder, data); err != nil {
		return "", fmt.Errorf("failed to execute tag template: %w", err)
	}

	return builder.String(), nil
}

func printSummary(results []patchJobStatus) {
	if len(results) == 0 {
		return
	}

	var buf bytes.Buffer
	writer := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)

	fmt.Fprintln(writer, "NAME\tSTATUS\tSOURCE IMAGE\tPATCHED TAG\tDETAILS")

	for _, res := range results {
		details := "OK"
		if res.Error != nil {
			details = res.Error.Error()
		}
		row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", res.Name, res.Status, res.Source, res.Target, details)
		fmt.Fprintln(writer, row)
	}

	writer.Flush()
	log.Infof("\n\nBulk Patch Summary:\n%s", buf.String())
}
