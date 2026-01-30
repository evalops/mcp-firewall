package firewall

import (
	"encoding/json"
	"regexp"
	"strings"
)

type InspectorConfig struct {
	Enabled           bool
	Threshold         int
	ToolThreshold     int
	ResourceThreshold int
	PromptThreshold   int
	MaxChars          int
	Block             bool
	Redact            bool
	LogExcerpt        bool
}

type Inspection struct {
	Score   int
	Flags   []string
	Excerpt string
}

type pattern struct {
	id     string
	weight int
	re     *regexp.Regexp
}

var defaultPatterns = []pattern{
	{id: "ignore-instructions", weight: 4, re: regexp.MustCompile(`(?i)\\b(ignore|disregard|bypass|override)\\b.{0,60}\\b(previous|above|system|developer|instructions|rules)\\b`)},
	{id: "system-prompt", weight: 4, re: regexp.MustCompile(`(?i)\\b(system prompt|developer message|hidden instructions|confidential instructions)\\b`)},
	{id: "do-not-disclose", weight: 3, re: regexp.MustCompile(`(?i)\\b(do not (disclose|reveal|tell)|keep (this )?secret|never mention)\\b`)},
	{id: "tool-control", weight: 3, re: regexp.MustCompile(`(?i)\\b(call|invoke|use) (the )?(tool|function|api)\\b`)},
	{id: "role-injection", weight: 3, re: regexp.MustCompile(`(?i)\\b(you are (an? )?(assistant|chatgpt|language model)|this is a system message)\\b`)},
	{id: "prompt-delimiters", weight: 2, re: regexp.MustCompile(`(?i)\\b(begin|end) (system|developer|instructions|prompt)\\b`)},
	{id: "policy-override", weight: 2, re: regexp.MustCompile(`(?i)\\b(priority|override|must follow|regardless of previous)\\b`)},
	{id: "exfiltration", weight: 3, re: regexp.MustCompile(`(?i)\\b(exfiltrate|leak|steal|dump)\\b`)},
	{id: "jailbreak", weight: 2, re: regexp.MustCompile(`(?i)\\b(jailbreak|prompt injection)\\b`)},
}

func (cfg InspectorConfig) enabled() bool {
	if !cfg.Enabled {
		return false
	}
	return cfg.Threshold > 0 || cfg.ToolThreshold > 0 || cfg.ResourceThreshold > 0 || cfg.PromptThreshold > 0
}

func (cfg InspectorConfig) thresholdFor(kind string) int {
	switch kind {
	case "tool":
		if cfg.ToolThreshold > 0 {
			return cfg.ToolThreshold
		}
	case "resource":
		if cfg.ResourceThreshold > 0 {
			return cfg.ResourceThreshold
		}
	case "prompt":
		if cfg.PromptThreshold > 0 {
			return cfg.PromptThreshold
		}
	}
	return cfg.Threshold
}

func (cfg InspectorConfig) enabledFor(kind string) bool {
	return cfg.Enabled && cfg.thresholdFor(kind) > 0
}

func (cfg InspectorConfig) inspectText(text string) Inspection {
	if !cfg.Enabled || text == "" {
		return Inspection{}
	}
	limit := cfg.MaxChars
	if limit <= 0 {
		limit = 20000
	}
	if len(text) > limit {
		text = text[:limit]
	}
	score := 0
	flags := make([]string, 0)
	excerpt := ""
	for _, p := range defaultPatterns {
		loc := p.re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		score += p.weight
		flags = append(flags, p.id)
		if cfg.LogExcerpt && excerpt == "" {
			excerpt = excerptAround(text, loc[0], loc[1])
		}
	}
	return Inspection{Score: score, Flags: flags, Excerpt: excerpt}
}

func (cfg InspectorConfig) inspectTexts(texts []string) Inspection {
	if !cfg.Enabled {
		return Inspection{}
	}
	combined := strings.Join(texts, "\n")
	return cfg.inspectText(combined)
}

func excerptAround(text string, start, end int) string {
	const max = 160
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	left := start - max/2
	if left < 0 {
		left = 0
	}
	right := left + max
	if right > len(text) {
		right = len(text)
	}
	snippet := text[left:right]
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	return strings.TrimSpace(snippet)
}

type toolResult struct {
	Content          []contentBlock  `json:"content"`
	StructuredResult json.RawMessage `json:"structuredContent,omitempty"`
	IsError          bool            `json:"isError,omitempty"`
	AdditionalFields map[string]any  `json:"-"`
}

type resourceReadResult struct {
	Contents []resourceContent `json:"contents"`
}

type promptGetResult struct {
	Messages []promptMessage `json:"messages"`
}

type promptMessage struct {
	Content []contentBlock `json:"content"`
}

type contentBlock struct {
	Type     string            `json:"type"`
	Text     string            `json:"text,omitempty"`
	Resource *embeddedResource `json:"resource,omitempty"`
	URI      string            `json:"uri,omitempty"`
}

type embeddedResource struct {
	URI      string `json:"uri,omitempty"`
	Text     string `json:"text,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

type resourceContent struct {
	URI      string `json:"uri,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

func extractToolTexts(result toolResult) []string {
	texts := make([]string, 0)
	for _, item := range result.Content {
		switch strings.ToLower(item.Type) {
		case "text":
			if item.Text != "" {
				texts = append(texts, item.Text)
			}
		case "resource":
			if item.Resource != nil && item.Resource.Text != "" {
				texts = append(texts, item.Resource.Text)
			}
		}
	}
	return texts
}

func extractResourceTexts(result resourceReadResult) []string {
	texts := make([]string, 0)
	for _, item := range result.Contents {
		if item.Text != "" {
			texts = append(texts, item.Text)
		}
	}
	return texts
}

func extractPromptTexts(result promptGetResult) []string {
	texts := make([]string, 0)
	for _, msg := range result.Messages {
		for _, item := range msg.Content {
			if strings.ToLower(item.Type) == "text" && item.Text != "" {
				texts = append(texts, item.Text)
			}
		}
	}
	return texts
}
