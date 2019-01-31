package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	goflag "flag"

	raven "github.com/getsentry/raven-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/golang/glog"
	"github.com/spf13/cobra"

	"github.com/autonubil/default-backend-operator/pkg/backend"
	"github.com/autonubil/default-backend-operator/pkg/operator"
)

var (
	cmdName = "default-backend-operator"
	usage   = fmt.Sprintf("%s", cmdName)
)

// Fatal prints the message (if provided) and then exits. If V(2) or greater,
// glog.Fatal is invoked for extended information.
func fatal(msg string) {
	if glog.V(2) {
		glog.FatalDepth(2, msg)
	}
	if len(msg) > 0 {
		// add newline if needed
		if !strings.HasSuffix(msg, "\n") {
			msg += "\n"
		}
		fmt.Fprint(os.Stderr, msg)
	}
	os.Exit(1)
}

// NewCmdOptions creates an options Cobra command to return usage
func NewCmdOptions() *cobra.Command {
	cmd := &cobra.Command{
		Use: "options",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Usage()
		},
	}

	return cmd
}

// Create a new command for the DefaultBackend-operator. This cmd includes logging,
// cmd option parsing from flags, and the customization of the Tectonic assets.
func NewCmdDefaultBackendOperator() (*cobra.Command, error) {
	// Define the options for DefaultBackendOperator command
	options, err := operator.NewBackendOperatorOptions()

	if err != nil {
		return nil, err
	}

	// Create a new command
	cmd := &cobra.Command{
		Use:   usage,
		Short: "",
		Run: func(cmd *cobra.Command, args []string) {
			checkErr(Run(cmd, options), fatal)
		},
	}

	// Bind & parse flags defined by external projects.
	// e.g. This imports the golang/glog pkg flags into the cmd flagset
	cmd.Flags().AddGoFlagSet(goflag.CommandLine)
	goflag.CommandLine.Parse([]string{})

	// Define the flags allowed in this command & store each option provided
	// as a flag, into the DefaultBackendOperatorOptions

	cmd.Flags().StringVarP(&options.KubeConfig, "kubeconfig", "", options.KubeConfig, "Path to a kube config. Only required if out-of-cluster.")
	cmd.Flags().StringVarP(&options.Namespace, "namespace", "n", options.Namespace, "Namespace to watch for annotated configMaps in. If no namespace is provided, NAMESPACE env. var is used. Lastly, the '' (any namespaces) will be used as a last option.")
	cmd.Flags().BoolVarP(&options.PrometheusEnabled, "prometheus", "p", options.PrometheusEnabled, "Enable Prometheus metrics on port 9350. If not specified PROMETHEUS_ENABLES env. var is checked for existence")

	cmd.Flags().BoolVarP(&options.TemplatePath, "template", "t", options.PrometheusEnabled, "Template file that renders to valid HTML")
	cmd.Flags().BoolVarP(&options.StaticsPath, "statics", "s", options.PrometheusEnabled, "Static entries")

	return cmd, nil
}

func serveMetrics() {
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":9350", nil)
	glog.V(2).Infoln("Startet listening for prometheus metrics requests")
}

func serveBackend(options *operator.BackendOperatorOptions) {
	// Listen for requests:
	http.Handle("/", &backend.BackendHandler{Options: options})
	http.ListenAndServe(":8081", nil)
	glog.V(2).Infoln("Startet listening for backend requests")
}

// Run the customization of the Tectonic assets
func Run(cmd *cobra.Command, options *operator.BackendOperatorOptions) error {

	configTags := make(map[string]string)
	if options.Namespace != "" {
		configTags["Namespace"] = options.Namespace
	}
	if options.PrometheusEnabled || len(os.Getenv("PROMETHEUS_ENABLED")) > 0 {
		configTags["PrometheusEnabled"] = "true"
	}

	raven.Capture(&raven.Packet{Level: raven.INFO, Message: "Started Default Backend Operator"}, configTags)

	if options.PrometheusEnabled || len(os.Getenv("PROMETHEUS_ENABLED")) > 0 {
		go serveMetrics()
	}

	/*
		cntlr, err := operator.NewDefaultBackendController(
			options.KubeConfig, options.Namespace)

		if err != nil {
			return err
		}
	*/

	// Start backend server:
	go serveBackend(options)

	// Relay OS signals to the chan
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	// Example: Create a new AppMontior & instantiate it in the cluster
	// am := operator.NewAppMonitor("my-app-monitor", 80, 2)
	// am.Instantiate(options.KubeConfig, options.Namespace)

	stop := make(chan struct{})

	watchIngressCntlr, err := operator.NewingressConfigController(options)

	if err != nil {
		return err
	}
	go watchIngressCntlr.Start(stop)

	/*
		go cntlr.Start(stop)
	*/
	// Block until signaled to stop
	<-signals

	// Close the stop chan / shutdown the controller
	close(stop)

	glog.Infof("Shutting down Default Backend Operator...")
	raven.Capture(&raven.Packet{Level: raven.INFO, Message: "Stopped Default Backend Operator"}, map[string]string{})

	return nil
}

func checkErr(err error, handleErr func(string)) {
	if err == nil {
		return
	}

	raven.CaptureError(err, map[string]string{"operation": "checkErr"})

	handleErr(err.Error())
}
