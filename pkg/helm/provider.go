package helm

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"code.cloudfoundry.org/lager"
	"github.com/autonubil/default-backend-operator/pkg/utils/pathorcontents"
	"github.com/autonubil/default-backend-operator/pkg/utils/resource"
	homedir "github.com/mitchellh/go-homedir"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/helm/cmd/helm/installer"
	"k8s.io/helm/pkg/getter"
	"k8s.io/helm/pkg/helm"
	helm_env "k8s.io/helm/pkg/helm/environment"
	"k8s.io/helm/pkg/helm/helmpath"
	"k8s.io/helm/pkg/helm/portforwarder"
	"k8s.io/helm/pkg/kube"
	"k8s.io/helm/pkg/repo"

	"github.com/golang/glog"

	"github.com/autonubil/default-backend-operator/pkg/types"
)

type HelmProvider struct {
	Settings         *helm_env.EnvSettings
	TLSConfig        *tls.Config
	K8sClient        kubernetes.Interface
	K8sConfig        *rest.Config
	Tunnel           *kube.Tunnel
	DefaultNamespace string
	Options          *types.BackendOperatorOptions

	// Informer for all resources being watched by the operator.
	// informer *configMapControllerInformer

	// HelmConfiguration *helmConfig.HelmConfiguration
	// Mutex used for lock the Tiller installation and Tunnel creation.
	sync.Mutex
}

/*
// Implements an Informer for the resources being operated on: ingresss &
// ingressConfigs.
type configMapControllerInformer struct {
	// Store & controller for ingress resources
	configMapStore      cache.Store
	configMapController cache.Controller
}
*/

func RefreshHelm(options *types.BackendOperatorOptions) error {
	p, err := NewHelmProvider(options, true)
	if err != nil {
		glog.Error("Helm provider could not be initialized", err)
		return err
	}

	releases, err := p.ListReleases()
	if err != nil {
		glog.Error("Helm releases could not be listed", err)
		return err
	}

	glog.V(1).Infof("Read %d Helm releases", len(releases))
	for _, release := range releases {
		helmRelease := types.NewHelmRelease(release)
		options.Data.Releases[fmt.Sprintf("%s/%s",release.Namespace, release.Name)] = helmRelease
		glog.V(4).Infof("read Release: %s/%s -> \n--\n%v\n", release.Namespace, release.Name, helmRelease)
	}
	return nil
}

// init a new helm Provider
func NewHelmProvider(options *types.BackendOperatorOptions, connect bool) (*HelmProvider, error) {

	p := &HelmProvider{Options: options}
	p.buildSettings(p.Options.HelmConfiguration)

	if _, err := os.Stat(p.Settings.Home.String()); os.IsNotExist(err) {
		if err := p.initHome(); err != nil {
			return nil, err
		}
	}

	if connect {

		if err := p.buildTLSConfig(p.Options.HelmConfiguration); err != nil {
			return nil, err
		}

		if err := p.getK8sConfig(); err != nil {
			return nil, err
		}

		if err := p.initialize(); err != nil {
			return nil, err
		}
	}

	return p, nil
}

/*
// Start the ingressConfigController until stopped.
func (p *HelmProvider) Start(stop <-chan struct{}) {
	// Don't let panics crash the process
	defer utilruntime.HandleCrash()

	while(true) {
		time.Sleep(5000)
	}

	// Block until stopped
	<-stop
}
*/

// GetHelmClient will return a new Helm client
func (p *HelmProvider) GetHelmClient() (helm.Interface, error) {

	return p.buildHelmClient(), nil
}

func (p *HelmProvider) initialize() error {
	p.Lock()
	defer p.Unlock()

	if err := p.prepareTillerConnection(false); err != nil {
		return err
	}

	if err := p.buildTunnel(); err != nil {
		return err
	}

	return nil
}

func getContent(filename, def string) ([]byte, error) {

	content, _, err := pathorcontents.Read(filename)
	if err != nil {
		return nil, err
	}

	if content == def {
		return nil, nil
	}

	return []byte(content), nil
}

func (p *HelmProvider) buildSettings(c *types.HelmConfiguration) {
	p.Settings = &helm_env.EnvSettings{
		Home:                    helmpath.Home(c.Home),
		TillerHost:              c.Tiller.Host,
		TillerNamespace:         c.Tiller.Namespace,
		TillerConnectionTimeout: c.Tiller.ConnectionTimeout,
		Debug: c.Debug,
	}

	glog.Info("Helm Environment created", lager.Data{"HelmEnv": p.Settings})
}

func (p *HelmProvider) buildTLSConfig(c *types.HelmConfiguration) error {
	keyPEMBlock, err := getContent(c.ClientKey, "$HELM_HOME/key.pem")
	if err != nil {
		return err
	}
	certPEMBlock, err := getContent(c.ClientCertificate, "$HELM_HOME/cert.pem")
	if err != nil {
		return err
	}
	if len(keyPEMBlock) == 0 && len(certPEMBlock) == 0 {
		return nil
	}

	cfg := &tls.Config{
		InsecureSkipVerify: c.Insecure,
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return fmt.Errorf("could not read x509 key pair: %s", err)
	}

	cfg.Certificates = []tls.Certificate{cert}

	caPEMBlock, err := getContent(c.CaCertificate, "$HELM_HOME/ca.pem")
	if err != nil {
		return err
	}

	if !cfg.InsecureSkipVerify && len(caPEMBlock) != 0 {
		cfg.RootCAs = x509.NewCertPool()
		if !cfg.RootCAs.AppendCertsFromPEM(caPEMBlock) {
			return fmt.Errorf("failed to parse ca_certificate")
		}
	}

	p.TLSConfig = cfg
	return nil
}

func (p *HelmProvider) getK8sConfig() error {

	config, err := rest.InClusterConfig()

	if err == nil {
		glog.Info("Running inside a k8s cluster", lager.Data{"K8sHost": config.Host})
	} else {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		explicitPath, err := homedir.Expand(p.Options.HelmConfiguration.Kubernetes.ConfigPath)
		if err != nil {
			return err
		}

		rules.ExplicitPath = explicitPath
		rules.DefaultClientConfig = &clientcmd.DefaultClientConfig

		overrides := &clientcmd.ConfigOverrides{}

		context := p.Options.HelmConfiguration.Kubernetes.ConfigContext
		if context != "" {
			overrides.CurrentContext = context
		}

		config, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
		if err != nil {
			return err
		}
		glog.Info("Running outside a k8s cluster", lager.Data{"K8sConfig": config})
	}

	// Overriding with static configuration
	config.UserAgent = fmt.Sprintf("autonubil-service-broker/1.0 Helm/0.1.0")

	p.K8sConfig = config

	p.K8sClient, err = kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to configure kubernetes config: %s", err)
	}

	return nil
}

func (p *HelmProvider) waitForTillerService(o *installer.Options, timeout time.Duration) (*corev1.Service, error) {
	const service = "tiller-deploy"

	stateConf := &resource.StateChangeConf{
		Target:  []string{"Up"},
		Pending: []string{"Pending"},
		Timeout: timeout,
		Refresh: func() (interface{}, string, error) {
			glog.Info("Check for tiller-pod become available.")
			obj, err := p.K8sClient.CoreV1().Services(o.Namespace).Get(service, metav1.GetOptions{})

			if err != nil {
				glog.Error("Failed to get Tiller Service Status.", err, lager.Data{"Object": obj})
				return obj, "Error", err
			}
			glog.Info("Tiller Service Status.", lager.Data{"Object": obj})

			if len(obj.Spec.ClusterIP) > 0 {
				return obj, "Up", nil
			}

			return obj, "Pending", nil
		},
	}

	obj, err := stateConf.WaitForState()

	return obj.(*corev1.Service), err
}

func (p *HelmProvider) prepareTillerConnection(createIfMissing bool) error {
	o := &installer.Options{}
	o.Namespace = p.Options.HelmConfiguration.Tiller.Namespace
	o.ImageSpec = p.Options.HelmConfiguration.Tiller.Image
	o.ServiceAccount = p.Options.HelmConfiguration.Tiller.ServiceAccount

	o.EnableTLS = p.Options.HelmConfiguration.Tiller.EnableTLS

	if o.EnableTLS {
		o.TLSCertFile = p.Options.HelmConfiguration.Tiller.ClientCertificate
		o.TLSKeyFile = p.Options.HelmConfiguration.Tiller.ClientKey
		o.VerifyTLS = !p.Options.HelmConfiguration.Tiller.Insecure
		if o.VerifyTLS {
			o.TLSCaCertFile = p.Options.HelmConfiguration.Tiller.CaCertificate
		}
	}

	glog.Info("Checking for tiller installation", lager.Data{"TillerOptions": o})

	if err := p.waitForTiller(o, 10*time.Second); err != nil {
		glog.Info("tiller-deploy not found - trying to install tiller.", lager.Data{"Error": err})
		if createIfMissing {
			if err := installer.Install(p.K8sClient, o); err != nil {
				if errors.IsAlreadyExists(err) {
					glog.Info("Tiller is already installed")
				} else {
					return fmt.Errorf("error installing: %s", err)
				}
			}
			if err := p.waitForTiller(o, 5*time.Minute); err != nil {
				return err
			}
		} else {
			return err
		}
		glog.Info("Tiller has been installed into your Kubernetes Cluster.")
	} else {
		glog.Info("Tiller is already installed into your Kubernetes Cluster.")
	}

	obj, err := p.waitForTillerService(o, 5*time.Minute)
	if err != nil {
		return err
	}

	if obj != nil && len(obj.Spec.ClusterIP) > 0 && len(obj.Spec.Ports) > 0 {
		seconds := 5
		timeOut := time.Duration(seconds) * time.Second
		serviceEndpoint := fmt.Sprintf("%s:%d", obj.Spec.ClusterIP, obj.Spec.Ports[0].Port)
		_, err := net.DialTimeout("tcp", serviceEndpoint, timeOut)
		if err == nil {
			glog.Info("Tiller service is directly accessible", lager.Data{"target": serviceEndpoint})
			p.Settings.TillerHost = serviceEndpoint
		}
	}

	return nil
}

func (p *HelmProvider) waitForTiller(o *installer.Options, timeout time.Duration) error {
	const deployment = "tiller-deploy"
	stateConf := &resource.StateChangeConf{
		Target:  []string{"Running"},
		Pending: []string{"Pending"},
		Timeout: timeout,
		Refresh: func() (interface{}, string, error) {
			glog.Info("Check for tiller-deploy become available", lager.Data{"Namespace": o.Namespace, "deployment": deployment})
			obj, err := p.K8sClient.Extensions().Deployments(o.Namespace).Get(deployment, metav1.GetOptions{})
			if err != nil {
				glog.Error("Failed to get Tiller Deployment", err, lager.Data{"Namespace": o.Namespace, "deployment": deployment, "Object": obj.Status})
				return obj, "Error", err
			}

			glog.Info("Tiller Status", lager.Data{"Namespace": o.Namespace, "deployment": deployment, "Object": obj.Status})

			if obj.Status.ReadyReplicas > 0 {
				return obj, "Running", nil
			}

			return obj, "Pending", nil
		},
	}

	_, err := stateConf.WaitForState()
	return err
}

func (p *HelmProvider) buildTunnel() error {
	if p.Settings.TillerHost != "" {
		return nil
	}

	var err error
	p.Tunnel, err = portforwarder.New(p.Settings.TillerNamespace, p.K8sClient, p.K8sConfig)
	if err != nil {
		return fmt.Errorf("error creating tunnel: %q", err)
	}

	p.Settings.TillerHost = fmt.Sprintf("localhost:%d", p.Tunnel.Local)

	glog.Info("Created tunnel to tiller", lager.Data{"TillerHost": p.Settings.TillerHost, "LocalPort": p.Tunnel.Local, "PodName": p.Tunnel.PodName, "RemotePort": p.Tunnel.Remote, "Namespace": p.Tunnel.Namespace})
	return nil
}

func (p *HelmProvider) buildHelmClient() helm.Interface {
	options := []helm.Option{
		helm.Host(p.Settings.TillerHost),
		helm.ConnectTimeout(p.Settings.TillerConnectionTimeout),
	}

	if p.TLSConfig != nil {
		options = append(options, helm.WithTLS(p.TLSConfig))
	}

	return helm.NewClient(options...)
}

func (p *HelmProvider) initHome() error {

	if err := ensureDirectories(p.Settings.Home); err != nil {
		return err
	}
	if err := ensureDefaultRepos(*p.Settings, false); err != nil {
		return err
	}
	if err := ensureRepoFileFormat(p.Settings.Home.RepositoryFile()); err != nil {
		return err
	}
	glog.Info("$HELM_HOME has been configured", lager.Data{"HELM_HOME": p.Settings.Home})

	return nil
}

// ensureDirectories checks to see if $HELM_HOME exists.
//
// If $HELM_HOME does not exist, this function will create it.
func ensureDirectories(home helmpath.Home) error {
	configDirectories := []string{
		home.String(),
		home.Repository(),
		home.Cache(),
		home.LocalRepository(),
		home.Plugins(),
		home.Starters(),
		home.Archive(),
	}
	for _, p := range configDirectories {
		if fi, err := os.Stat(p); err != nil {
			glog.Info("Creating Directory", lager.Data{"Path": p})

			if err := os.MkdirAll(p, 0755); err != nil {
				return fmt.Errorf("Could not create %s: %s", p, err)
			}
		} else if !fi.IsDir() {
			return fmt.Errorf("%s must be a directory", p)
		}
	}

	return nil
}

func ensureDefaultRepos(settings helm_env.EnvSettings, skipRefresh bool) error {
	repoFile := settings.Home.RepositoryFile()
	if fi, err := os.Stat(repoFile); err != nil {
		glog.Info("Creating Repo File", lager.Data{"RepoFile": repoFile})
		f := repo.NewRepoFile()
		sr, err := initStableRepo(settings.Home.CacheIndex(stableRepository), skipRefresh, settings)
		if err != nil {
			return err
		}
		lr, err := initLocalRepo(settings.Home.LocalRepository(localRepositoryIndexFile), settings.Home.CacheIndex("local"))
		if err != nil {
			return err
		}
		f.Add(sr)
		f.Add(lr)
		if err := f.WriteFile(repoFile, 0644); err != nil {
			return err
		}
	} else if fi.IsDir() {
		return fmt.Errorf("%s must be a file, not a directory", repoFile)
	}
	return nil
}

func initStableRepo(cacheFile string, skipRefresh bool, settings helm_env.EnvSettings) (*repo.Entry, error) {
	glog.V(3).Infof("Adding Repo (%s, %s)", stableRepository, stableRepositoryURL)
	c := repo.Entry{
		Name:  stableRepository,
		URL:   stableRepositoryURL,
		Cache: cacheFile,
	}
	r, err := repo.NewChartRepository(&c, getter.All(settings))
	if err != nil {
		return nil, err
	}

	if skipRefresh {
		return &c, nil
	}

	// In this case, the cacheFile is always absolute. So passing empty string
	// is safe.
	if err := r.DownloadIndexFile(""); err != nil {
		return nil, fmt.Errorf("Looks like %q is not a valid chart repository or cannot be reached: %s", stableRepositoryURL, err.Error())
	}

	return &c, nil
}

func initLocalRepo(indexFile, cacheFile string) (*repo.Entry, error) {
	if fi, err := os.Stat(indexFile); err != nil {
		glog.V(3).Infof("Adding Repo (%s, %s)", localRepository, localRepositoryURL)
		i := repo.NewIndexFile()
		if err := i.WriteFile(indexFile, 0644); err != nil {
			return nil, err
		}

		//TODO: take this out and replace with helm update functionality
		if err := createLink(indexFile, cacheFile); err != nil {
			return nil, err
		}
	} else if fi.IsDir() {
		return nil, fmt.Errorf("%s must be a file, not a directory", indexFile)
	}

	return &repo.Entry{
		Name:  localRepository,
		URL:   localRepositoryURL,
		Cache: cacheFile,
	}, nil
}

func ensureRepoFileFormat(file string) error {
	r, err := repo.LoadRepositoriesFile(file)
	if err == repo.ErrRepoOutOfDate {
		glog.Info("Updating repository file format...")
		if err := r.WriteFile(file, 0644); err != nil {
			return err
		}
	}

	return nil
}

const (
	stableRepository         = "stable"
	localRepository          = "local"
	localRepositoryIndexFile = "index.yaml"
)

var (
	tlsCaCertFile       string // path to TLS CA certificate file
	tlsCertFile         string // path to TLS certificate file
	tlsKeyFile          string // path to TLS key file
	tlsVerify           bool   // enable TLS and verify remote certificates
	tlsEnable           bool   // enable TLS
	stableRepositoryURL = "https://kubernetes-charts.storage.googleapis.com"
	// This is the IPv4 loopback, not localhost, because we have to force IPv4
	// for Dockerized Helm: https://github.com/kubernetes/helm/issues/1410
	localRepositoryURL = "http://127.0.0.1:8879/charts"
)
