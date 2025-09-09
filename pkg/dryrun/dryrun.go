package dryrun

import (
	"context"
	"fmt"
	"strings"

	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	log "github.com/sirupsen/logrus"

	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/common"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
)

// Execute is the main entrypoint for the dry-run mode.
func Execute(ctx context.Context, opts *types.Options) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	log.Info("Checking for upgradable packages...")

	bkOpts := buildkit.Opts{
		Addr:       opts.BkAddr,
		CACertPath: opts.BkCACertPath,
		CertPath:   opts.BkCertPath,
		KeyPath:    opts.BkKeyPath,
	}
	bkClient, err := buildkit.NewClient(timeoutCtx, bkOpts)
	if err != nil {
		return fmt.Errorf("failed to initialize buildkit client for dry run: %w", err)
	}
	defer bkClient.Close()

	found, err := CheckUpgradablePackages(timeoutCtx, bkClient, opts)
	if err != nil {
		return fmt.Errorf("failed to check for upgradable packages: %w", err)
	}

	if found {
		log.Info("Result: Upgradable packages were found.")
	} else {
		log.Info("Result: No upgradable packages were found.")
	}
	return nil
}

// CheckUpgradablePackages runs a lightweight build to see if an image has pending OS updates.
func CheckUpgradablePackages(ctx context.Context, bkClient *client.Client, opts *types.Options) (bool, error) {
	var updatesFound bool
	var checkErr error

	_, err := bkClient.Build(ctx, client.SolveOpt{}, "copa-dry-run", func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		baseState := llb.Image(opts.Image, llb.WithMetaResolver(c))

		config := &buildkit.Config{ImageState: baseState}
		fileBytes, err := buildkit.ExtractFileFromState(ctx, c, &config.ImageState, "/etc/os-release")
		if err != nil {
			checkErr = fmt.Errorf("failed to extract /etc/os-release: %w", err)
			return nil, checkErr
		}
		osInfo, err := common.GetOSInfo(ctx, fileBytes)
		if err != nil {
			checkErr = err
			return nil, checkErr
		}
		manager, err := pkgmgr.GetPackageManager(osInfo.Type, osInfo.Version, config, "")
		if err != nil {
			checkErr = err
			return nil, checkErr
		}

		checkCmd, err := manager.GetCheckUpgradableCommand()
		if err != nil {
			checkErr = err
			return nil, checkErr
		}
		log.Debugf("Executing dry-run check command: %s", checkCmd)

		checkState := baseState.Run(llb.Shlex(checkCmd), llb.WithProxy(utils.GetProxy())).Root()
		def, err := checkState.Marshal(ctx)
		if err != nil {
			checkErr = fmt.Errorf("failed to marshal dry-run state: %w", err)
			return nil, checkErr
		}

		_, solveErr := c.Solve(ctx, gwclient.SolveRequest{Definition: def.ToPB()})

		if solveErr == nil {
			updatesFound = true
		} else if strings.Contains(solveErr.Error(), "process exited with status") {
			updatesFound = false
		} else if strings.Contains(solveErr.Error(), "not found") { // Specific check for image not found.
			checkErr = fmt.Errorf("image %q not found in registry or local daemon", opts.Image)
		} else {
			checkErr = fmt.Errorf("unexpected error during dry-run build: %w", solveErr)
		}

		return gwclient.NewResult(), nil
	}, nil)

	if err != nil {
		if checkErr != nil {
			return false, checkErr
		}
		return false, err
	}

	return updatesFound, nil
}
