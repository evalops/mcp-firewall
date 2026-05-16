package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"
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
	Classifier        ClassifierConfig
}

type Inspection struct {
	Score              int
	Flags              []string
	Excerpt            string
	ClassifierProvider string
	ClassifierScore    float64
	ClassifierLabel    string
}

type ClassifierConfig struct {
	Provider  string
	URL       string
	Headers   map[string]string
	Threshold float64
	Timeout   time.Duration
	Client    *http.Client
}

type classifierRequest struct {
	Provider string `json:"provider,omitempty"`
	Kind     string `json:"kind"`
	Text     string `json:"text"`
}

type classifierResponse struct {
	Score       float64  `json:"score"`
	Confidence  float64  `json:"confidence"`
	Probability float64  `json:"probability"`
	Label       string   `json:"label"`
	Action      string   `json:"action"`
	Flags       []string `json:"flags"`
	Categories  []string `json:"categories"`
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
	return cfg.Threshold > 0 || cfg.ToolThreshold > 0 || cfg.ResourceThreshold > 0 || cfg.PromptThreshold > 0 || cfg.Classifier.enabled()
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

func (cfg InspectorConfig) inspectText(ctx context.Context, kind string, text string) Inspection {
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
	inspection := Inspection{Score: score, Flags: flags, Excerpt: excerpt}
	if classifierInspection, err := cfg.Classifier.classify(ctx, kind, text); err == nil {
		inspection = mergeInspections(inspection, classifierInspection)
	}
	return inspection
}

func (cfg InspectorConfig) inspectTexts(ctx context.Context, kind string, texts []string) Inspection {
	if !cfg.Enabled {
		return Inspection{}
	}
	combined := strings.Join(texts, "\n")
	return cfg.inspectText(ctx, kind, combined)
}

func (cfg ClassifierConfig) enabled() bool {
	return strings.TrimSpace(cfg.URL) != ""
}

func (cfg ClassifierConfig) classify(ctx context.Context, kind string, text string) (Inspection, error) {
	if !cfg.enabled() || strings.TrimSpace(text) == "" {
		return Inspection{}, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	classifierCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	payload, err := json.Marshal(classifierRequest{
		Provider: strings.TrimSpace(cfg.Provider),
		Kind:     strings.TrimSpace(kind),
		Text:     text,
	})
	if err != nil {
		return Inspection{}, err
	}
	request, err := http.NewRequestWithContext(classifierCtx, http.MethodPost, cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return Inspection{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	for key, value := range cfg.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key != "" && value != "" {
			request.Header.Set(key, value)
		}
	}

	client := cfg.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return Inspection{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Inspection{}, fmt.Errorf("classifier returned HTTP %d", response.StatusCode)
	}
	var decoded classifierResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return Inspection{}, err
	}
	return cfg.inspectionFromResponse(decoded), nil
}

func (cfg ClassifierConfig) inspectionFromResponse(response classifierResponse) Inspection {
	score := firstPositiveFloat(response.Score, response.Confidence, response.Probability)
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = 0.5
	}
	label := strings.TrimSpace(response.Label)
	action := strings.ToLower(strings.TrimSpace(response.Action))
	flags := prefixedClassifierFlags(cfg.Provider, label, response.Flags, response.Categories)
	if score < threshold && label == "" && action != "block" && action != "deny" {
		return Inspection{ClassifierProvider: strings.TrimSpace(cfg.Provider), ClassifierScore: score}
	}
	contribution := int(math.Ceil(score * 10))
	if contribution <= 0 {
		contribution = 1
	}
	return Inspection{
		Score:              contribution,
		Flags:              flags,
		ClassifierProvider: strings.TrimSpace(cfg.Provider),
		ClassifierScore:    score,
		ClassifierLabel:    label,
	}
}

func prefixedClassifierFlags(provider string, label string, flags []string, categories []string) []string {
	prefix := strings.TrimSpace(provider)
	if prefix == "" {
		prefix = "classifier"
	}
	result := make([]string, 0, 1+len(flags)+len(categories))
	appendFlag := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			result = append(result, prefix+":"+value)
		}
	}
	appendFlag(label)
	for _, flag := range flags {
		appendFlag(flag)
	}
	for _, category := range categories {
		appendFlag(category)
	}
	if len(result) == 0 {
		result = append(result, prefix+":flagged")
	}
	return result
}

func mergeInspections(left Inspection, right Inspection) Inspection {
	left.Score += right.Score
	left.Flags = append(left.Flags, right.Flags...)
	if left.Excerpt == "" {
		left.Excerpt = right.Excerpt
	}
	if right.ClassifierProvider != "" {
		left.ClassifierProvider = right.ClassifierProvider
		left.ClassifierScore = right.ClassifierScore
		left.ClassifierLabel = right.ClassifierLabel
	}
	return left
}

func firstPositiveFloat(values ...float64) float64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
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
