package main

import (
	"fmt"
	"os"

	k8slogsutil "k8s.io/apiserver/pkg/util/logs"

	"github.com/autonubil/default-backend-operator/pkg/cmd"
	"github.com/getsentry/raven-go"
	"github.com/golang/glog"
)

var Version string
var Commit string
var BuildDate string

func main() {
	// init sentry if configured
	sentryDsn := os.Getenv("SENTRY_DSN")
	if len(sentryDsn) > 0 {
		raven.SetDSN(sentryDsn)
		raven.SetRelease(fmt.Sprintf("%s [%s@%s]", Version, Commit, BuildDate))
		// Make sure that the call to doStuff doesn't leak a panic
		raven.CapturePanic(run, nil)
	} else {
		run()
	}
}

func run() {
	// Create & execute new command
	cmd, err := cmd.NewCmdDefaultBackendOperator()
	if err != nil {
		os.Exit(1)
	}

	// Init logging
	k8slogsutil.InitLogs()
	defer k8slogsutil.FlushLogs()

	glog.Infof("Starting Default Backend Operator [Version %s, Commit: %s, BuildDate: %s]", Version, Commit, BuildDate)

	err = cmd.Execute()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
