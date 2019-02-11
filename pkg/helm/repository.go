package helm

import (
	"errors"
	"fmt"
	"os"

	"code.cloudfoundry.org/lager"

	"k8s.io/helm/pkg/getter"
	"k8s.io/helm/pkg/helm/helmpath"
	"k8s.io/helm/pkg/repo"

	"github.com/golang/glog"
)

// ErrRepositoryNotFound is the error when a Helm repository is not found
var ErrRepositoryNotFound = errors.New("repository not found")

func (p *HelmProvider) EnsureRepositories() error {

	for _, r := range p.Options.HelmConfiguration.Repositories {
		_, err := p.getRepository(r.Name)
		if err != nil {
			glog.V(3).Infof("Repository %s is not installed yet", r.Name)
		}

		if r.ClientCertificate != "" {
			if _, err := os.Stat("r.CaCertificate"); os.IsNotExist(err) {
				glog.Error("Repo CaCertificate not found ", err, lager.Data{"Repository": r.Name, "Url": r.URL, "CaCertificate": r.CaCertificate})
				return err
			}
		}

		// allways add (if exists a refresh will be done)
		err = p.addRepository(r.Name, r.URL, p.Settings.Home, r.ClientCertificate, r.ClientKey, r.CaCertificate, false)
		if err != nil {
			glog.Error("Failed to read repo", err, lager.Data{"Repository": r.Name, "Url": r.URL, "CaCertificate": r.CaCertificate})
			return err
		}
	}
	return nil

}

// from helm
func (p *HelmProvider) getRepository(name string) (*repo.Entry, error) {
	f, err := repo.LoadRepositoriesFile(p.Settings.Home.RepositoryFile())
	if err != nil {
		return nil, err
	}

	for _, r := range f.Repositories {
		if r.Name == name {
			return r, nil
		}
	}

	return nil, ErrRepositoryNotFound

}

func (p *HelmProvider) addRepository(
	name, url string, home helmpath.Home, certFile, keyFile, caFile string, noUpdate bool,
) error {

	f, err := repo.LoadRepositoriesFile(home.RepositoryFile())
	if err != nil {
		return err
	}

	if noUpdate && f.Has(name) {
		return fmt.Errorf("repository name (%s) already exists, please specify a different name", name)
	}

	cif := home.CacheIndex(name)
	c := repo.Entry{
		Name:     name,
		Cache:    cif,
		URL:      url,
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}

	if caFile != "" && (certFile == "" || keyFile == "") {
		return fmt.Errorf("you specified a RootCA file without specifying a mutual TLS configuration - the CA is only used for mutual TLS")
	}

	r, err := repo.NewChartRepository(&c, getter.All(*p.Settings))
	if err != nil {
		return err
	}

	if err := r.DownloadIndexFile(home.Cache()); err != nil {
		return fmt.Errorf("Looks like %q is not a valid chart repository or cannot be reached: %s", url, err.Error())
	}

	f.Update(&c)

	return f.WriteFile(home.RepositoryFile(), 0644)
}

func removeRepoLine(name string, home helmpath.Home) error {
	repoFile := home.RepositoryFile()
	r, err := repo.LoadRepositoriesFile(repoFile)
	if err != nil {
		return err
	}

	if !r.Remove(name) {
		return fmt.Errorf("no repo named %q found", name)
	}
	if err := r.WriteFile(repoFile, 0644); err != nil {
		return err
	}

	if err := removeRepoCache(name, home); err != nil {
		return err
	}

	return nil
}

func removeRepoCache(name string, home helmpath.Home) error {
	if _, err := os.Stat(home.CacheIndex(name)); err == nil {
		err = os.Remove(home.CacheIndex(name))
		if err != nil {
			return err
		}
	}
	return nil
}
