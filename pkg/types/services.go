package types

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/golang/glog"

	extensionsv1beta "k8s.io/api/extensions/v1beta1"

	"k8s.io/helm/pkg/proto/hapi/chart"
)

type Service struct {
	ID           string              `json:"id"`
	Index        uint64              `json:"index"`
	Type         string              `json:"type"`
	Name         string              `json:"name"`
	Namespace    string              `json:"namespace"`
	Application  string              `json:"application"`
	URL          string              `json:"url"`
	Visibility   string              `json:"visibility"`
	Description  string              `json:"description,ommitempty"`
	Icon         string              `json:"icon,ommitempty"`
	Overlay      string              `json:"overlay,ommitempty"`
	Tags         Tags                `json:"tags,ommitempty"`
	Keywords     []string            `json:"keywords,ommitempty"`
	AppVersion   string              `json:"appVersion,ommitempty"`
	Sources      []string            `json:"sources,ommitempty"`
	Home         string              `json:"home,ommitempty"`
	Maintainers  []*chart.Maintainer `json:"maintainers,ommitempty"`
	ChartName    string              `json:"chartName,ommitempty"`
	ChartVersion string              `json:"chartVersion,ommitempty"`
	Info         string              `json:"info,ommitempty"`
	hidden       bool                `json:"hidden,ommit"`
}

type ServiceKeyValue struct {
	Key   string
	Value *Service
}

func (s *Service) HasTag(tag string) bool {
	for _, val := range s.Tags {
		if val == tag {
			return true
		}
	}
	return false
}

func (p ServiceKeyValueList) Less(i, j int) bool {
	//	glog.V(1).Infof("%s: %v | %s -> %v", p[i].Value.Name, p[i].Value.HasTag("public"), p[j].Value.Name, !p[i].Value.HasTag("private") || p[i].Value.Name < p[j].Value.Name)
	if p[i].Value.HasTag("public") && !p[j].Value.HasTag("public") {
		return true
	}
	if p[i].Value.Index < p[j].Value.Index {
		return true
	}
	return p[i].Value.Index == p[j].Value.Index && p[i].Value.Name < p[j].Value.Name
}

func filterServices(s []*Service) []*Service {
	result := make([]*Service, 0)
	for _, svc := range s {
		if svc.hidden {
			continue
		}

		result = append(result, svc)
	}
	return result
}

func SortServices(s map[string]*Service) []*Service {
	if len(s) == 0 {
		return []*Service{}
	}
	p := make(ServiceKeyValueList, len(s))
	i := 0
	for k, v := range s {
		p[i] = ServiceKeyValue{k, v}
		i++
	}
	sort.Sort(p)
	result := make([]*Service, 0)
	for _, v := range p {
		if v.Value != nil {
			result = append(result, v.Value)
		}
	}
	return filterServices(result)
}

func (d *BackendOperatorOptions) NewService(ingress *extensionsv1beta.Ingress) *Service {
	svc := &Service{
		ID:        string(ingress.UID),
		Type:      "Ingress",
		Index:     100,
		Name:      ingress.Name,
		Namespace: ingress.Namespace,
	}

	for _, rule := range ingress.Spec.Rules {
		svc.URL = fmt.Sprintf("http://%s", rule.Host)
		break
	}

	d.autoImage(ingress, svc)
	d.addReleaseInfo(ingress, svc)
	d.getVisibility(ingress, svc)

	d.addAnnotatons(ingress, svc)

	return svc
}

func (d *BackendOperatorOptions) autoImage(ingress *extensionsv1beta.Ingress, svc *Service) {
	if d.StaticsPath != "" {
		name := strings.ToLower(svc.Name)
		if _, err := os.Stat(d.StaticsPath + "/" + name + ".svg"); err == nil {
			svc.Icon = "/static/" + name + ".svg"
			return
		}

		// hostname?
		for _, rule := range ingress.Spec.Rules {
			parts := strings.Split(rule.Host, ".")
			if _, err := os.Stat(d.StaticsPath + "/" + parts[0] + ".svg"); err == nil {
				svc.Icon = "/static/" + parts[0] + ".svg"
				return
			}
			break
		}

		// first or last part of release name?
		parts := strings.Split(name, "-")
		if len(parts) > 1 {
			if _, err := os.Stat(d.StaticsPath + "/" + parts[len(parts)-1] + ".svg"); err == nil {
				svc.Icon = "/static/" + parts[len(parts)-1] + ".svg"
				return
			}

			if _, err := os.Stat(d.StaticsPath + "/" + parts[0] + ".svg"); err == nil {
				svc.Icon = "/static/" + parts[0] + ".svg"
				return
			}
		}

	}

}

func (d *BackendOperatorOptions) getVisibility(ingress *extensionsv1beta.Ingress, svc *Service) {
	url, err := url.Parse(svc.URL)
	if err == nil {
		ips, err := net.LookupIP(url.Host)
		if err == nil {
			glog.V(4).Infof("Host %s resolved to %v", url.Host, ips)
			isPrivat := false
			for _, ip := range ips {
				for _, block := range privateIPBlocks {
					if block.Contains(ip) {
						isPrivat = true
						break
					}
				}
			}
			if isPrivat {
				svc.Visibility = "private"
			} else {
				svc.Visibility = "public"
			}
		} else {
			glog.V(3).Infof("Could not resolve host %s", url.Host)
		}
	} else {
		glog.V(3).Infof("Could not parse URL %s", svc.URL)
	}

}

func (d *BackendOperatorOptions) addAnnotatons(ingress *extensionsv1beta.Ingress, svc *Service) {
	if value, exists := ingress.ObjectMeta.Annotations["wallaby.autonubuil.net/index"]; exists {
		val, err := strconv.ParseUint(value, 10, 32)
		if err == nil {
			svc.Index = val
		} else {
			glog.Error("Could not parse index value '%s' for ingress annotation wallaby.autonubuil.net/index at  %s/%s", value, ingress.Namespace, ingress.Name)
		}
	}

	if value, exists := ingress.ObjectMeta.Annotations["wallaby.autonubuil.net/name"]; exists {
		svc.Name = value
	}

	if value, exists := ingress.ObjectMeta.Annotations["wallaby.autonubuil.net/description"]; exists {
		svc.Description = value
	}

	if value, exists := ingress.ObjectMeta.Annotations["wallaby.autonubuil.net/icon"]; exists {
		svc.Icon = value
	}
	if value, exists := ingress.ObjectMeta.Annotations["wallaby.autonubuil.net/overlay"]; exists {
		svc.Overlay = value
	}
	if value, exists := ingress.ObjectMeta.Annotations["wallaby.autonubuil.net/tags"]; exists {
		svc.Tags.SetAll(strings.Split(value, ","))
	}

	// labeled as "hidden?"
	if value, exists := ingress.ObjectMeta.Annotations["wallaby.autonubil.net/hidden"]; exists {
		b, err := strconv.ParseBool(value)
		if err != nil || b {
			svc.hidden = true
		}
	}

}

func (d *BackendOperatorOptions) addReleaseInfo(ingress *extensionsv1beta.Ingress, svc *Service) bool {
	chart := ""
	release := ""
	if chartLabelValue, exists := ingress.ObjectMeta.Labels["chart"]; exists {
		chart = chartLabelValue
	} else if chartLabelValue, exists := ingress.ObjectMeta.Labels["helm.sh/chart"]; exists {
		chart = chartLabelValue
	}
	if chart != "" {
		chartParts := strings.Split(chart, "-")
		svc.ChartVersion = chartParts[len(chartParts)-1]
		svc.ChartName = strings.Join(chartParts[:len(chartParts)-1], "-")
	}

	if releaseLabelValue, exists := ingress.ObjectMeta.Labels["release"]; exists {
		release = releaseLabelValue
	} else if releaseLabelValue, exists := ingress.ObjectMeta.Labels["app.kubernetes.io/instance"]; exists {
		release = releaseLabelValue
	}

	if appNameLabelValue, exists := ingress.ObjectMeta.Labels["app"]; exists {
		svc.Application = appNameLabelValue
	} else if appNameLabelValue, exists := ingress.ObjectMeta.Labels["app.kubernetes.io/name"]; exists {
		svc.Application = appNameLabelValue
	}

	helmRelease := d.Data.Releases[fmt.Sprintf("%s/%s", ingress.Namespace, release)]

	if helmRelease == nil {
		return false
	}

	svc.Tags.SetAll(helmRelease.ChartMetadata.Keywords)
	svc.Home = helmRelease.ChartMetadata.Home

	svc.ChartName = helmRelease.ChartMetadata.Name
	svc.ChartVersion = helmRelease.ChartMetadata.Version

	svc.Description = helmRelease.ChartMetadata.Description
	// svc.Name = helmRelease.ChartMetadata.Name
	if svc.Application == "" {
		svc.Application = helmRelease.ChartMetadata.Name
	}
	svc.Maintainers = helmRelease.ChartMetadata.Maintainers
	if svc.Icon == "" {
		svc.Icon = helmRelease.ChartMetadata.Icon
	}
	svc.Info = helmRelease.Info.Status.Notes
	svc.AppVersion = helmRelease.ChartMetadata.AppVersion

	return true
}
