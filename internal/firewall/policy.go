package firewall

import (
	"net/url"
	"path"
	"strings"
)

type RuleSet struct {
	Allow           []string `yaml:"allow"`
	Deny            []string `yaml:"deny"`
	Strict          bool     `yaml:"strict"`
	CaseInsensitive bool     `yaml:"case_insensitive"`
}

type MatchDetail struct {
	Rule    string `json:"rule,omitempty" yaml:"rule,omitempty"`
	Pattern string `json:"pattern,omitempty" yaml:"pattern,omitempty"`
}

func (r RuleSet) Allowed(value string) (bool, string) {
	allowed, reason, _ := r.AllowedMatch(value)
	return allowed, reason
}

func (r RuleSet) AllowedMatch(value string) (bool, string, MatchDetail) {
	if ok, pattern := matchAny(r.Deny, value, r.CaseInsensitive); ok {
		return false, "matched deny list", MatchDetail{Rule: "deny", Pattern: pattern}
	}
	if len(r.Allow) > 0 {
		if ok, pattern := matchAny(r.Allow, value, r.CaseInsensitive); ok {
			return true, "", MatchDetail{Rule: "allow", Pattern: pattern}
		}
		return false, "not in allow list", MatchDetail{Rule: "allow", Pattern: ""}
	}
	if r.Strict {
		return false, "default deny (strict)", MatchDetail{Rule: "default-deny"}
	}
	return true, "", MatchDetail{Rule: "default-allow"}
}

type ResourceRules struct {
	Allow           []string `yaml:"allow"`
	Deny            []string `yaml:"deny"`
	AllowSchemes    []string `yaml:"allow_schemes"`
	DenySchemes     []string `yaml:"deny_schemes"`
	Strict          bool     `yaml:"strict"`
	CaseInsensitive bool     `yaml:"case_insensitive"`
	Normalize       bool     `yaml:"normalize"`
}

func (r ResourceRules) Allowed(uri string) (bool, string) {
	allowed, reason, _ := r.AllowedMatch(uri)
	return allowed, reason
}

func (r ResourceRules) AllowedMatch(uri string) (bool, string, MatchDetail) {
	normalized := normalizeResourceURI(uri, r.Normalize)
	scheme := schemeOf(normalized)
	if ok, pattern := matchAny(r.DenySchemes, scheme, true); ok {
		return false, "scheme denied", MatchDetail{Rule: "deny_schemes", Pattern: pattern}
	}
	if ok, pattern := matchAny(r.Deny, normalized, r.CaseInsensitive); ok {
		return false, "resource denied", MatchDetail{Rule: "deny", Pattern: pattern}
	}
	if len(r.AllowSchemes) > 0 {
		if ok, pattern := matchAny(r.AllowSchemes, scheme, true); ok {
			return true, "", MatchDetail{Rule: "allow_schemes", Pattern: pattern}
		}
		return false, "scheme not in allow list", MatchDetail{Rule: "allow_schemes"}
	}
	if len(r.Allow) > 0 {
		if ok, pattern := matchAny(r.Allow, normalized, r.CaseInsensitive); ok {
			return true, "", MatchDetail{Rule: "allow", Pattern: pattern}
		}
		return false, "resource not in allow list", MatchDetail{Rule: "allow"}
	}
	if r.Strict {
		return false, "default deny (strict)", MatchDetail{Rule: "default-deny"}
	}
	return true, "", MatchDetail{Rule: "default-allow"}
}

type Policy struct {
	Methods   RuleSet       `yaml:"methods"`
	Tools     RuleSet       `yaml:"tools"`
	Prompts   RuleSet       `yaml:"prompts"`
	Resources ResourceRules `yaml:"resources"`
	Metadata  PolicyMeta    `yaml:"metadata,omitempty"`
}

type PolicyMeta struct {
	Tools       int      `yaml:"tools,omitempty"`
	Resources   int      `yaml:"resources,omitempty"`
	Prompts     int      `yaml:"prompts,omitempty"`
	Schemes     []string `yaml:"schemes,omitempty"`
	GeneratedAt string   `yaml:"generated_at,omitempty"`
	Note        string   `yaml:"note,omitempty"`
}

func schemeOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "local"
	}
	return strings.ToLower(u.Scheme)
}

func matchAny(patterns []string, value string, caseInsensitive bool) (bool, string) {
	value = strings.TrimSpace(value)
	if caseInsensitive {
		value = strings.ToLower(value)
	}
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		candidate := strings.TrimSpace(pattern)
		if caseInsensitive {
			candidate = strings.ToLower(candidate)
		}
		if ok, _ := path.Match(candidate, value); ok {
			return true, pattern
		}
	}
	return false, ""
}

func normalizeResourceURI(raw string, normalize bool) string {
	value := strings.TrimSpace(raw)
	if !normalize || value == "" {
		return value
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" {
		return value
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Scheme == "file" && u.Host == "localhost" {
		u.Host = ""
	}
	if u.Scheme == "http" && strings.HasSuffix(u.Host, ":80") {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	}
	if u.Scheme == "https" && strings.HasSuffix(u.Host, ":443") {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	}
	if u.Path != "" {
		if decoded, err := url.PathUnescape(u.Path); err == nil {
			u.Path = decoded
		}
		u.Path = path.Clean(u.Path)
		if !strings.HasPrefix(u.Path, "/") {
			u.Path = "/" + u.Path
		}
	}
	return u.String()
}
