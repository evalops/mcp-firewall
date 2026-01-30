package firewall

import (
	"encoding/json"
	"fmt"
	"strings"
)

type pendingRequest struct {
	method     string
	name       string
	uri        string
	scheme     string
	rule       string
	pattern    string
	normalized string
	requestID  string
	traceID    string
}

type responseOutcome struct {
	modified   bool
	blocked    bool
	reason     string
	inspection Inspection
	threshold  int
}

func (p *Proxy) processResponse(pending pendingRequest, msg *rpcMessage) (responseOutcome, error) {
	outcome := responseOutcome{}
	if msg.Result == nil {
		return outcome, nil
	}
	if !p.Enabled() {
		return outcome, nil
	}
	policy := p.currentPolicy()

	switch pending.method {
	case "tools/list":
		var res toolListResult
		if err := json.Unmarshal(msg.Result, &res); err == nil {
			filtered := make([]toolDef, 0, len(res.Tools))
			for _, tool := range res.Tools {
				if allowed, _ := policy.Tools.Allowed(tool.Name); allowed {
					filtered = append(filtered, tool)
				}
			}
			if len(filtered) != len(res.Tools) {
				res.Tools = filtered
				if updated, err := json.Marshal(res); err == nil {
					msg.Result = updated
					outcome.modified = true
				}
			}
		}
	case "resources/list":
		var res resourceListResult
		if err := json.Unmarshal(msg.Result, &res); err == nil {
			filtered := make([]resourceDef, 0, len(res.Resources))
			for _, resource := range res.Resources {
				if allowed, _ := policy.Resources.Allowed(resource.URI); allowed {
					filtered = append(filtered, resource)
				}
			}
			if len(filtered) != len(res.Resources) {
				res.Resources = filtered
				if updated, err := json.Marshal(res); err == nil {
					msg.Result = updated
					outcome.modified = true
				}
			}
		}
	case "prompts/list":
		var res promptListResult
		if err := json.Unmarshal(msg.Result, &res); err == nil {
			filtered := make([]promptDef, 0, len(res.Prompts))
			for _, prompt := range res.Prompts {
				if allowed, _ := policy.Prompts.Allowed(prompt.Name); allowed {
					filtered = append(filtered, prompt)
				}
			}
			if len(filtered) != len(res.Prompts) {
				res.Prompts = filtered
				if updated, err := json.Marshal(res); err == nil {
					msg.Result = updated
					outcome.modified = true
				}
			}
		}
	case "tools/call":
		var res toolResult
		if err := json.Unmarshal(msg.Result, &res); err == nil {
			if removed := filterToolResources(policy.Resources, &res); removed > 0 {
				outcome.modified = true
			}
			threshold := p.inspect.thresholdFor("tool")
			outcome.threshold = threshold
			outcome.inspection = p.inspect.inspectTexts(extractToolTexts(res))
			if p.inspect.enabledFor("tool") && outcome.inspection.Score >= threshold {
				outcome.reason = fmt.Sprintf("suspicious tool output (%s)", strings.Join(outcome.inspection.Flags, ","))
				if p.inspect.Block {
					outcome.blocked = true
				} else if p.inspect.Redact {
					if redactToolTexts(&res) {
						outcome.modified = true
					}
				}
			}
			if outcome.modified {
				if updated, err := json.Marshal(res); err == nil {
					msg.Result = updated
				}
			}
		}
	case "resources/read":
		var res resourceReadResult
		if err := json.Unmarshal(msg.Result, &res); err == nil {
			if removed := filterResourceContents(policy.Resources, &res); removed > 0 {
				outcome.modified = true
			}
			threshold := p.inspect.thresholdFor("resource")
			outcome.threshold = threshold
			outcome.inspection = p.inspect.inspectTexts(extractResourceTexts(res))
			if p.inspect.enabledFor("resource") && outcome.inspection.Score >= threshold {
				outcome.reason = fmt.Sprintf("suspicious resource content (%s)", strings.Join(outcome.inspection.Flags, ","))
				if p.inspect.Block {
					outcome.blocked = true
				} else if p.inspect.Redact {
					if redactResourceTexts(&res) {
						outcome.modified = true
					}
				}
			}
			if outcome.modified {
				if updated, err := json.Marshal(res); err == nil {
					msg.Result = updated
				}
			}
		}
	case "prompts/get":
		var res promptGetResult
		if err := json.Unmarshal(msg.Result, &res); err == nil {
			threshold := p.inspect.thresholdFor("prompt")
			outcome.threshold = threshold
			outcome.inspection = p.inspect.inspectTexts(extractPromptTexts(res))
			if p.inspect.enabledFor("prompt") && outcome.inspection.Score >= threshold {
				outcome.reason = fmt.Sprintf("suspicious prompt content (%s)", strings.Join(outcome.inspection.Flags, ","))
				if p.inspect.Block {
					outcome.blocked = true
				} else if p.inspect.Redact {
					if redactPromptTexts(&res) {
						outcome.modified = true
					}
				}
			}
			if outcome.modified {
				if updated, err := json.Marshal(res); err == nil {
					msg.Result = updated
				}
			}
		}
	}

	return outcome, nil
}

func filterToolResources(rules ResourceRules, res *toolResult) int {
	removed := 0
	filtered := res.Content[:0]
	for _, item := range res.Content {
		uri := item.URI
		if uri == "" && item.Resource != nil {
			uri = item.Resource.URI
		}
		if uri != "" {
			if allowed, _ := rules.Allowed(uri); !allowed {
				removed++
				continue
			}
		}
		filtered = append(filtered, item)
	}
	res.Content = filtered
	return removed
}

func filterResourceContents(rules ResourceRules, res *resourceReadResult) int {
	removed := 0
	filtered := res.Contents[:0]
	for _, item := range res.Contents {
		if item.URI != "" {
			if allowed, _ := rules.Allowed(item.URI); !allowed {
				removed++
				continue
			}
		}
		filtered = append(filtered, item)
	}
	res.Contents = filtered
	return removed
}

func redactToolTexts(res *toolResult) bool {
	changed := false
	for idx := range res.Content {
		item := &res.Content[idx]
		switch strings.ToLower(item.Type) {
		case "text":
			if item.Text != "" {
				item.Text = "[redacted by mcp-firewall]"
				changed = true
			}
		case "resource":
			if item.Resource != nil && item.Resource.Text != "" {
				item.Resource.Text = "[redacted by mcp-firewall]"
				changed = true
			}
		}
	}
	return changed
}

func redactResourceTexts(res *resourceReadResult) bool {
	changed := false
	for idx := range res.Contents {
		item := &res.Contents[idx]
		if item.Text != "" {
			item.Text = "[redacted by mcp-firewall]"
			changed = true
		}
	}
	return changed
}

func redactPromptTexts(res *promptGetResult) bool {
	changed := false
	for mi := range res.Messages {
		msg := &res.Messages[mi]
		for ci := range msg.Content {
			item := &msg.Content[ci]
			if strings.ToLower(item.Type) == "text" && item.Text != "" {
				item.Text = "[redacted by mcp-firewall]"
				changed = true
			}
		}
	}
	return changed
}
