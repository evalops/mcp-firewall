package firewall

import (
	"net/url"
	"path"
	"strings"
)

type RuleSet struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

func (r RuleSet) Allowed(value string) (bool, string) {
	if matchAny(r.Deny, value) {
		return false, "matched deny list"
	}
	if len(r.Allow) > 0 && !matchAny(r.Allow, value) {
		return false, "not in allow list"
	}
	return true, ""
}

type ResourceRules struct {
	Allow        []string `yaml:"allow"`
	Deny         []string `yaml:"deny"`
	AllowSchemes []string `yaml:"allow_schemes"`
	DenySchemes  []string `yaml:"deny_schemes"`
}

func (r ResourceRules) Allowed(uri string) (bool, string) {
	scheme := schemeOf(uri)
	if matchAny(r.DenySchemes, scheme) {
		return false, "scheme denied"
	}
	if matchAny(r.Deny, uri) {
		return false, "resource denied"
	}
	if len(r.AllowSchemes) > 0 && !matchAny(r.AllowSchemes, scheme) {
		return false, "scheme not in allow list"
	}
	if len(r.Allow) > 0 && !matchAny(r.Allow, uri) {
		return false, "resource not in allow list"
	}
	return true, ""
}

type Policy struct {
	Methods   RuleSet       `yaml:"methods"`
	Tools     RuleSet       `yaml:"tools"`
	Prompts   RuleSet       `yaml:"prompts"`
	Resources ResourceRules `yaml:"resources"`
}

func schemeOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "local"
	}
	return strings.ToLower(u.Scheme)
}

func matchAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		if ok, _ := path.Match(pattern, value); ok {
			return true
		}
	}
	return false
}
