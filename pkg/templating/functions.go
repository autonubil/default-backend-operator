package templating

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"html/template"

	"github.com/Masterminds/sprig"

	yaml "gopkg.in/yaml.v2"
)

func FuncMap() template.FuncMap {
	f := sprig.FuncMap()
	extra := template.FuncMap{
		"md5sum":   md5sum,
		"toYaml":   ToYaml,
		"fromYaml": FromYaml,
		"fromJson": FromJson,
	}

	for k, v := range extra {
		f[k] = v
	}

	return f
}

func md5sum(input string) string {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:])
}

// ToYaml takes an interface, marshals it to yaml, and returns a string. It will
// always return a string, even on marshal error (empty string).
//
// This is designed to be called from a template.
func ToYaml(v interface{}) string {
	data, err := yaml.Marshal(v)
	if err != nil {
		// Swallow errors inside of a template.
		return ""
	}
	return string(data)
}

// FromYaml converts a YAML document into a map[string]interface{}.
//
// This is not a general-purpose YAML parser, and will not parse all valid
// YAML documents. Additionally, because its intended use is within templates
// it tolerates errors. It will insert the returned error message string into
// m["Error"] in the returned map.
func FromYaml(str string) map[string]interface{} {
	m := map[string]interface{}{}

	if err := yaml.Unmarshal([]byte(str), &m); err != nil {
		m["Error"] = err.Error()
	}
	return m
}

// FromJson converts a YAML document into a map[string]interface{}.
//
// This is not a general-purpose JSON parser, and will not parse all valid
// YAML documents. Additionally, because its intended use is within templates
// it tolerates errors. It will insert the returned error message string into
// m["Error"] in the returned map.
func FromJson(str string) map[string]interface{} {
	m := map[string]interface{}{}

	if err := json.Unmarshal([]byte(str), &m); err != nil {
		m["Error"] = err.Error()
	}
	return m
}
