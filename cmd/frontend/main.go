package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"

	"github.com/moby/buildkit/frontend/gateway/grpcclient"
	"github.com/moby/buildkit/util/appcontext"
	"github.com/moby/buildkit/util/bklog"
	"github.com/project-copacetic/copacetic/pkg/frontend"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/grpclog"
)

func init() {
	bklog.L.Logger.SetOutput(os.Stderr)
	grpclog.SetLoggerV2(grpclog.NewLoggerV2WithVerbosity(bklog.L.WriterLevel(logrus.InfoLevel), bklog.L.WriterLevel(logrus.WarnLevel), bklog.L.WriterLevel(logrus.ErrorLevel), 1))
}

func main() {
	fs := flag.CommandLine
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `usage: %s [args...]`, os.Args[0])
	}

	if err := fs.Parse(os.Args); err != nil {
		bklog.L.WithError(err).Fatal("error parsing frontend args")
		os.Exit(70) // 70 is EX_SOFTWARE, meaning internal software error occurred
	}

	if err := grpcclient.RunFromEnvironment(appcontext.Context(), frontend.Build); err != nil {
		bklog.L.WithError(err).Fatal("error running frontend")
		os.Exit(70) // 70 is EX_SOFTWARE, meaning internal software error occurred
	}
}
