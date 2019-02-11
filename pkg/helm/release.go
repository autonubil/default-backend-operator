package helm

import (
	"errors"
	"strings"

	"code.cloudfoundry.org/lager"
	yaml "gopkg.in/yaml.v2"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"k8s.io/helm/pkg/helm"
	"k8s.io/helm/pkg/proto/hapi/release"
	rls "k8s.io/helm/pkg/proto/hapi/services"

	"github.com/autonubil/default-backend-operator/pkg/types"
	hapi_release5 "k8s.io/helm/pkg/proto/hapi/release"
)

// ErrRepositoryNotFound is the error when a Helm repository is not found
var ErrReleaseNotFound = errors.New("release not found")

// dereived from https://github.com/mcuadros/terraform-provider-helm/blob/f7d11f747a9a6e609316c4b0ee36ec4405e0b6bb/helm/resource_release.go

func (p *HelmProvider) GetReleaseStatus(info *types.ReleaseInfo) (release.Status_Code, error) {
	r, err := p.GetRelease(info)

	if err != nil {
		return release.Status_UNKNOWN, err
	}

	status := r.Info.Status.Code

	glog.Info("Release Status ", lager.Data{"release": info.Name, "status": status})

	return status, nil //setIDAndMetadataFromRelease(res.Release)
}

func (p *HelmProvider) GetRelease(info *types.ReleaseInfo) (*release.Release, error) {
	c, err := p.GetHelmClient()
	if err != nil {
		return nil, err
	}

	r, err := getRelease(c, info.Name)

	if err != nil {
		return nil, err
	}

	return r, nil //setIDAndMetadataFromRelease(res.Release)
}

func (p *HelmProvider) ListReleases() ([]*hapi_release5.Release, error) {
	c, err := p.GetHelmClient()
	if err != nil {
		return nil, err
	}

	r, err := listReleases(c)

	if err != nil {
		return nil, err
	}

	return r.Releases, nil //setIDAndMetadataFromRelease(res.Release)
}

func getValues(base map[string]interface{}) ([]byte, error) {

	yaml, err := yaml.Marshal(base)
	if err == nil {
		glog.Info("values.yaml", lager.Data{"yaml": yaml})
	}

	return yaml, err
}

var all = []release.Status_Code{
	release.Status_UNKNOWN,
	release.Status_DEPLOYED,
	release.Status_DELETED,
	release.Status_DELETING,
	release.Status_FAILED,
}

func listReleases(client helm.Interface) (*rls.ListReleasesResponse, error) {
	res, err := client.ListReleases(
		helm.ReleaseListLimit(999),
		// helm.ReleaseListOffset(0),
		//		helm.ReleaseListFilter(l.filter),
		helm.ReleaseListSort(int32(rls.ListSort_CHART_NAME)),
		helm.ReleaseListOrder(int32(rls.ListSort_ASC)),
		helm.ReleaseListStatuses([]hapi_release5.Status_Code{
			hapi_release5.Status_UNKNOWN,
			hapi_release5.Status_DEPLOYED,
			hapi_release5.Status_FAILED,
			hapi_release5.Status_PENDING_INSTALL,
			hapi_release5.Status_PENDING_UPGRADE,
			hapi_release5.Status_PENDING_ROLLBACK,
		}),
	//	helm.ReleaseListNamespace(l.namespace),
	)
	if err != nil {
		msg := grpc.ErrorDesc(err)
		if strings.Contains(msg, "not found") {
			return nil, ErrReleaseNotFound
		}
		return nil, err
	}

	glog.V(2).Infof("listed %d releases", res.Count)

	return res, nil
}

func getRelease(client helm.Interface, name string) (*release.Release, error) {
	res, err := client.ReleaseContent(name)
	if err != nil {
		msg := grpc.ErrorDesc(err)
		if strings.Contains(msg, "not found") {
			return nil, ErrReleaseNotFound
		}
		return nil, err
	}

	glog.V(3).Infof("got release (%S/%s [%s] %s)", res.Release.Namespace, res.Release.Name, res.Release.Version, res.Release.Info.Status)

	return res.Release, nil
}
