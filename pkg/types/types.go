package types

import (
	"context"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/golang/glog"

	"github.com/autonubil/default-backend-operator/pkg/templating"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"k8s.io/helm/pkg/proto/hapi/chart"
	"k8s.io/helm/pkg/proto/hapi/release"
)

var privateIPBlocks []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

// A slice of Pairs that implements sort.Interface to sort by Value.
type ServiceKeyValueList []ServiceKeyValue

func (p ServiceKeyValueList) Swap(i, j int) { p[i], p[j] = p[j], p[i] }
func (p ServiceKeyValueList) Len() int      { return len(p) }

type Data struct {
	Services map[string]*Service     `json:"services"`
	Releases map[string]*HelmRelease `json:"releases"`
}
type TemplateData struct {
	Services   []*Service              `json:"services"`
	Releases   map[string]*HelmRelease `json:"releases"`
	OidcConfig OidcConfig
	Claims     *KnownClaims
}

func (d *BackendOperatorOptions) InitTemplateData() *TemplateData {
	result := &TemplateData{
		OidcConfig: OidcConfig{},
	}
	result.Services = SortServices(d.Data.Services)
	result.Releases = d.Data.Releases
	result.OidcConfig.Config.ClientID = d.OidcConfig.Config.ClientID
	result.OidcConfig.Config.ClientSecret = d.OidcConfig.Config.ClientSecret
	result.OidcConfig.Config.Scopes = d.OidcConfig.Config.Scopes
	result.OidcConfig.Config.Endpoint = d.OidcConfig.Config.Endpoint
	result.OidcConfig.Provider = d.OidcConfig.Provider
	result.OidcConfig.Enforce = d.OidcConfig.Enforce
	result.OidcConfig.Issuer = d.OidcConfig.Issuer

	return result
}

/**
Helm and Chart Configuratiuon
*/
type HelmConfiguration struct {
	Verify            bool               `yaml:"verify"`
	Insecure          bool               `yaml:"insecure"`
	ClientKey         string             `yaml:"clientKey"`
	ClientCertificate string             `yaml:"clientCertificate"`
	CaCertificate     string             `yaml:"caCertificate"`
	Keyring           string             `yaml:"keyring"`
	Home              string             `yaml:"home"`
	Tiller            TillerConfig       `yaml:"tiller"`
	Debug             bool               `yaml:"debug"`
	Kubernetes        KubernetesConfig   `yaml:"kubernetes"`
	Repositories      []RepositoryConfig `yaml:"repositories"`
}

type KubernetesConfig struct {
	ConfigPath    string `yaml:"configPath"`
	ConfigContext string `yaml:"configContext"`
}

type ChartConfig struct {
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	Repository string `yaml:"repository"`
	Devel      bool   `yaml:"devel"`
}

type RepositoryConfig struct {
	URL               string `yaml:"url"`
	Name              string `yaml:"name"`
	ClientKey         string `yaml:"clientKey"`
	ClientCertificate string `yaml:"client_certificate"`
	CaCertificate     string `yaml:"ca_certificate"`
}

type TillerConfig struct {
	Host              string `yaml:"host"`
	Namespace         string `yaml:"namespace"`
	Image             string `yaml:"image"`
	ServiceAccount    string `yaml:"service_account"`
	EnableTLS         bool   `yaml:"enableTls"`
	Insecure          bool   `yaml:"insecure"`
	ConnectionTimeout int64  `yaml:"connection_timeout"`
	ClientKey         string `yaml:"clientKey"`
	ClientCertificate string `yaml:"client_certificate"`
	CaCertificate     string `yaml:"ca_certificate"`
}

type HelmRelease struct {
	// Name is the name of the release
	Name string
	// Version is an int32 which represents the version of the release.
	Version int32
	// Namespace is the kubernetes namespace of the release.
	Namespace string

	// Info provides information about a release
	Info *release.Info
	// Chart is the chart that was released.
	ChartMetadata *chart.Metadata

	// Manifest string
}

type ReleaseParameters struct {
	Namespace string                 `yaml:"namespace"`
	Overrides map[string]interface{} `yaml:"overrides"`
}

type ReleaseInfo struct {
	Name         string                 `yaml:"name"`
	Namespace    string                 `yaml:"namespace"`
	Values       map[string]interface{} `yaml:"values"`
	Wait         bool                   `yaml:"wait"`
	RecreatePods bool                   `yaml:"recreate_pods"`
	ForceUpdate  bool                   `yaml:"force_update"`
}

func NewHelmRelease(release *release.Release) *HelmRelease {
	return &HelmRelease{
		Name:          release.Name,
		Version:       release.Version,
		Namespace:     release.Namespace,
		Info:          release.Info,
		ChartMetadata: release.Chart.Metadata,
		// Manifest:      release.Manifest,
	}
}

type BackendOperatorOptions struct {
	KubeConfig        string
	Namespace         string
	HelmConfiguration *HelmConfiguration
	PrometheusEnabled bool
	Label             string
	EntriesPath       string
	TemplatePath      string
	StaticsPath       string
	OidcConfig        OidcConfig
	Template          *template.Template
	Data              *Data
}

type OidcConfig struct {
	oauth2.Config
	Enforce    bool
	Issuer     string
	LoginURL   string
	LogoutURL  string
	Provider   *oidc.Provider
	ScopeFlags ScopeFlags
}

func (o *OidcConfig) InitProvider() error {

	if o.Issuer != "" {
		// see: https://github.com/coreos/go-oidc/blob/v2/example/userinfo/app.go
		ctx := context.Background()
		o.Config.Scopes = o.ScopeFlags

		provider, err := oidc.NewProvider(ctx, o.Issuer)
		if err != nil {
			glog.Error("Failed to get oidc information from well known endpoiunt", err)
			return err
		} else {
			o.Config.Endpoint = provider.Endpoint()
		}
		o.Provider = provider
	}
	return nil
}

type ScopeFlags []string

func (i *ScopeFlags) Type() string {
	return "ScopeFlags"
}

func (i *ScopeFlags) String() string {
	return strings.Join(([]string)(*i), ",")
}

func (i *ScopeFlags) Set(value string) error {
	for _, val := range *i {
		if val == value {
			return nil
		}
	}
	*i = append(*i, value)
	return nil
}

type Tags []string

func (i *Tags) Type() string {
	return "Tags"
}

func (i *Tags) String() string {
	return strings.Join(([]string)(*i), ",")
}

func (i *Tags) Set(value string) error {
	v := strings.TrimSpace(value)
	if v == "" {
		return nil
	}
	for _, val := range *i {
		if val == value {
			return nil
		}
	}
	*i = append(*i, value)
	return nil
}

func (i *Tags) SetAll(values []string) error {
	for _, val := range values {
		err := i.Set(val)
		if err != nil {
			return err
		}
	}
	return nil
}

func NewBackendOperatorOptions() *BackendOperatorOptions {
	result := &BackendOperatorOptions{
		Data: &Data{
			Services: make(map[string]*Service),
			Releases: make(map[string]*HelmRelease),
		},
		HelmConfiguration: &HelmConfiguration{
			Keyring: os.ExpandEnv("$HOME/.gnupg/pubring.gpg"),
			Home:    os.ExpandEnv("$HOME/.helm/"),
			Tiller: TillerConfig{
				Namespace:         "kube-system",
				ConnectionTimeout: 60,
			},
		},
		OidcConfig: OidcConfig{
			Enforce:    false,
			ScopeFlags: []string{"openid", "email", "profile"},
		},
	}

	return result
}

// refresh the Statics
func (opts *BackendOperatorOptions) RefreshStatics() error {
	if opts.EntriesPath == "" {
		opts.Data.Services = make(map[string]*Service)
	} else {
		statics, err := ioutil.ReadFile(opts.EntriesPath)
		if err != nil {
			return err
		}
		err = json.Unmarshal(statics, &opts.Data)
		if err != nil {
			return err
		}
		glog.V(2).Infof("Using entries from %s", opts.EntriesPath)
	}
	return nil
}

// refresh the Template
func (opts *BackendOperatorOptions) RefreshTemplate() error {
	if opts.TemplatePath != "" {
		src, err := ioutil.ReadFile(opts.TemplatePath)
		if err != nil {
			return err
		}

		opts.Template, err = template.New("base").Funcs(templating.FuncMap()).Parse(string(src))

		if err != nil {
			return err
		}

		glog.V(2).Infof("Using template  %s", opts.TemplatePath)
	}
	return nil
}

// read configuration from files
func (opts *BackendOperatorOptions) InitData() error {
	err := opts.RefreshStatics()

	if err != nil {
		return err
	}
	err = opts.RefreshTemplate()
	if err != nil {
		return err
	}

	return nil
}

type StandardClaims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

type AllowedOrigins []string

type EmailClaim struct {
	Email         string `json:"email,ommitempty"`
	EmailVerified bool   `json:"email_verified,ommitempty"`
}

type ProfileClaim struct {
	Name              string `json:"name,ommitempty"`
	PreferredUsername string `json:"preferred_username,ommitempty"`
	Locale            string `json:"locale,ommitempty"`
	GivenName         string `json:"given_name,ommitempty"`
	Picture           string `json:"picture,ommitempty"`
	Website           string `json:"website,ommitempty"`
	Zoneinfo          string `json:"zoneinfo,ommitempty"`
	Gender            string `json:"gender,ommitempty"`
	UpdatedAt         uint64 `json:"updated_at,ommitempty"`
}

type RoleList []string

type RoleMapping struct {
	Roles RoleList `json:"roles,ommitempty"`
}

type RealmAccessClaim struct {
	RealmAccess RoleMapping `json:"realm_access,ommitempty"`
}

type ResourceccessClaimMap map[string]RoleMapping

type KnownClaims struct {
	StandardClaims
	EmailClaim
	ProfileClaim
	AllowedOrigins AllowedOrigins `json:"allowed-origins,ommitempty"`
	RealmAccessClaim
	ResourceAccess ResourceccessClaimMap `json:"resource_access,ommitempty"`
	Scope          string                `json:"scope,ommitempty"`
}

/*

{
  "jti": "d6ae1ff3-3a52-4e4f-a084-5cd3c9e93988",
  "exp": 1549615800,
  "nbf": 0,
  "iat": 1549614900,
  "iss": "https://keycloak.autonubil.net/auth/realms/autonubil",
  "aud": "account",
  "sub": "5d12c0a7-085d-449b-afd5-82038575e867",
  "typ": "Bearer",
  "azp": "autonubil-wallaby",
  "auth_time": 0,
  "session_state": "d67a8229-5c08-43de-8936-5d6ad5ef02cf",
  "acr": "1",
  "allowed-origins": [
    "http://localhost:8080",
    "http://localhost:8081",
    "https://wallaby.autonubil.net",
    "https://www.autonubil.net"
  ],
  "realm_access": {
    "roles": [
      "internal",
      "rancher-user",
      "offline_access",
      "uma_authorization",
      "employee"
    ]
  },
  "resource_access": {
    "autonubil-wallaby": {
      "roles": [
        "admin",
        "user"
      ]
    },
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid phone email address profile",
  "address": {},
  "email_verified": true,
  "name": "Carsten Zeumer",
  "preferred_username": "carsten.zeumer",
  "locale": "de",
  "given_name": "Carsten",
  "family_name": "Zeumer",
  "email": "carsten.zeumer@autonubil.de"
}
*/
