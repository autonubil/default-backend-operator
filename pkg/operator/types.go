package operator

import (
	"encoding/json"
	 "fmt"
    "os"
)

type Service struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Namespace   string   `json:"namespace"`
	URL         string   `json:"url"`
	Description string   `json:"description,ommitempty"`
	Icon        string   `json:"icon,ommitempty"`
	Overlay     string   `json:"overlay,ommitempty"`
	Tags        []string `json:"tags,ommitempty"`
}

type Services struct {
	Services map[string]*Service `json:"services"`
}

type BackendOperatorOptions struct {
	KubeConfig        string
	Namespace         string
	PrometheusEnabled bool
	Label             string

	StaticsPath  string
	TemplatePath string

	Data *Services
}

func NewBackendOperatorOptions(staticsPath string) (*BackendOperatorOptions, error) {
	options := &BackendOperatorOptions{}

	if staticsPath == "" {
		options.Data = &Services{
			Services: make(map[string]*Service),
		}

	} else {
		statics, err := os.Open(staticsPath)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshall(statics, &options.Data)
		if err != nil {
			return nil, err
		}
	}
	return options, null
}
