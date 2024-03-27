package buildkit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"

	"github.com/moby/buildkit/client"
	gateway "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/solver/pb"
	"github.com/moby/buildkit/util/apicaps"
	"github.com/project-copacetic/copacetic/pkg/buildkit/connhelpers"
	log "github.com/sirupsen/logrus"
)

const (
	DefaultAddr = "unix:///run/buildkit/buildkitd.sock"
)

var (
	errMissingCap = fmt.Errorf("missing required buildkit functionality")
	// requiredCaps are buildkit llb ops required to function.
	requiredCaps = []apicaps.CapID{pb.CapMergeOp, pb.CapDiffOp}
)

// NewClient returns a new buildkit client with the given addr.
// If addr is empty it will first try to connect to docker's buildkit instance and then fallback to DefaultAddr.
func NewClient(ctx context.Context, bkOpts Opts) (*client.Client, error) {
	if bkOpts.Addr == "" {
		return autoClient(ctx)
	}
	opts := getCredentialOptions(bkOpts)
	client, err := client.New(ctx, bkOpts.Addr, opts...)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func getCredentialOptions(bkOpts Opts) []client.ClientOpt {
	opts := []client.ClientOpt{}
	if bkOpts.CACertPath != "" {
		opts = append(opts, client.WithServerConfig(getServerNameFromAddr(bkOpts.Addr), bkOpts.CACertPath))
	}

	if bkOpts.CertPath != "" || bkOpts.KeyPath != "" {
		opts = append(opts, client.WithCredentials(bkOpts.CertPath, bkOpts.KeyPath))
	}

	return opts
}

func getServerNameFromAddr(addr string) string {
	u, err := url.Parse(addr)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// ValidateClient checks to ensure the connected buildkit instance supports the features required by copa.
func ValidateClient(ctx context.Context, c *client.Client) error {
	_, err := c.Build(ctx, client.SolveOpt{}, "", func(_ context.Context, client gateway.Client) (*gateway.Result, error) {
		capset := client.BuildOpts().LLBCaps
		var err error
		for _, cap := range requiredCaps {
			err = errors.Join(err, capset.Supports(cap))
		}
		if err != nil {
			return nil, errors.Join(err, errMissingCap)
		}
		return &gateway.Result{}, nil
	}, nil)
	return err
}

func autoClient(ctx context.Context, opts ...client.ClientOpt) (*client.Client, error) {
	var retErr error

	newClient := func(ctx context.Context, dialer func(context.Context, string) (net.Conn, error)) (*client.Client, error) {
		client, err := client.New(ctx, "", append(opts, client.WithContextDialer(dialer))...)
		if err == nil {
			err = ValidateClient(ctx, client)
			if err == nil {
				return client, nil
			}
			client.Close()
		}
		return nil, err
	}

	log.Debug("Trying docker driver")
	h, err := connhelpers.Docker(&url.URL{})
	if err != nil {
		return nil, err
	}
	c, err := newClient(ctx, h.ContextDialer)
	if err == nil {
		return c, nil
	}
	log.WithError(err).Debug("Could not use docker driver")
	retErr = errors.Join(retErr, fmt.Errorf("could not use docker driver: %w", err))

	log.Debug("Trying buildx driver")
	h, err = connhelpers.Buildx(&url.URL{})
	if err != nil {
		return nil, err
	}

	c, err = newClient(ctx, h.ContextDialer)
	if err == nil {
		return c, nil
	}
	log.WithError(err).Debug("Could not use buildx driver")
	retErr = errors.Join(retErr, fmt.Errorf("could not use buildx driver: %w", err))

	log.Debug("Trying default buildkit addr")
	c, err = client.New(ctx, DefaultAddr, opts...)
	if err == nil {
		if err := ValidateClient(ctx, c); err == nil {
			return c, nil
		}
		c.Close()
	}
	log.WithError(err).Debug("Could not use buildkitd driver")
	return nil, errors.Join(retErr, fmt.Errorf("could not use buildkitd driver: %w", err))
}
