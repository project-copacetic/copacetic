package bulk

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"os"
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

func PatchFromConfig(ctx context.Context, configPath string, opts OrchestratorOptions) error {
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

	var wg sync.WaitGroup
	var mu sync.Mutex

	errChan := make(chan error, 1000)
	results := make([]patchJobStatus, 0)

	log.Infof("Starting bulk patch for %d image(s) defined in %s...", len(config.Images), configPath)

	for _, imageSpec := range config.Images {
		wg.Add(1)

		go func(spec ImageSpec) {
			defer wg.Done()

			tagsToPatch, err := FindTagsToPatch(ctx, spec)
			if err != nil {
				errChan <- fmt.Errorf("error discovering tags for '%s': %w", spec.Name, err)
				return
			}

			if len(tagsToPatch) == 0 {
				log.Warnf("No tags found to patch for '%s', skipping.", spec.Name)
				return
			}
			log.Infof("For '%s', found %d tag(s) to patch: %v", spec.Name, len(tagsToPatch), tagsToPatch)

			var innerWg sync.WaitGroup
			for _, tag := range tagsToPatch {
				innerWg.Add(1)

				go func(t string) {
					defer innerWg.Done()

					imageWithTag := fmt.Sprintf("%s:%s", spec.Image, t)
					targetTag, err := resolveTargetTag(spec.Target, t)
					if err != nil {
						errChan <- fmt.Errorf("error resolving target tag for '%s:%s': %w", spec.Name, t, err)
						return
					}

					log.Infof("--> Starting patch for %s", imageWithTag)

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
						log.Errorf("--> Failed to patch %s: %v", imageWithTag, err)
					} else {
						jobResult.Status = "Patched"
						log.Infof("--> Successfully patched %s -> %s", imageWithTag, targetTag)
					}
					results = append(results, jobResult)
					mu.Unlock()

				}(tag)
			}
			innerWg.Wait()
		}(imageSpec)
	}

	wg.Wait()
	close(errChan)

	printSummary(results)

	var multiErr *multierror.Error
	for err := range errChan {
		multiErr = multierror.Append(multiErr, err)
	}

	log.Info("Bulk patch run completed.")
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

	fmt.Fprintln(writer, "NAME\tSOURCE IMAGE\tPATCHED TAG\tSTATUS\tDETAILS")

	for _, res := range results {
		details := "OK"
		if res.Error != nil {
			details = res.Error.Error()
		}
		row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", res.Name, res.Source, res.Target, res.Status, details)
		fmt.Fprintln(writer, row)
	}

	writer.Flush()
	log.Infof("\n\n--- Bulk Patch Summary ---\n%s", buf.String())
}
