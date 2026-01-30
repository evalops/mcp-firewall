package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"mcp-firewall/internal/firewall/uiapi"
)

type uiBackend struct {
	core       *Proxy
	logger     *Logger
	history    *PolicyHistory
	allowWrite bool
	policyPath string
	mode       string
	upstream   string
}

func newUIBackend(core *Proxy, logger *Logger, history *PolicyHistory, allowWrite bool, policyPath string, mode string, upstream string) uiapi.Backend {
	backend := &uiBackend{
		core:       core,
		logger:     logger,
		history:    history,
		allowWrite: allowWrite,
		policyPath: policyPath,
		mode:       mode,
		upstream:   upstream,
	}
	backend.bootstrapHistory()
	return backend
}

func (b *uiBackend) Status() uiapi.Status {
	policy := b.core.CurrentPolicy()
	current := ""
	if b.history != nil {
		current, _ = b.history.List(1)
	}
	sandbox := b.core.Sandbox()
	enabled := b.core.Enabled()
	return uiapi.Status{
		Ready:                    true,
		Mode:                     b.mode,
		Upstream:                 b.upstream,
		EnforcementMode:          b.core.EnforcementMode(),
		DryRun:                   b.core.DryRun(),
		InspectEnabled:           b.core.InspectEnabled(),
		InspectThreshold:         b.core.InspectThreshold(),
		InspectToolThreshold:     b.core.InspectToolThreshold(),
		InspectResourceThreshold: b.core.InspectResourceThreshold(),
		InspectPromptThreshold:   b.core.InspectPromptThreshold(),
		Tools:                    len(policy.Tools.Allow),
		Resources:                len(policy.Resources.Allow),
		Prompts:                  len(policy.Prompts.Allow),
		PolicyWritable:           b.allowWrite,
		PolicyVersion:            current,
		NoNetwork:                sandbox.NoNetwork,
		SandboxBestEffort:        sandbox.BestEffort,
		AllowedBins:              append([]string(nil), sandbox.AllowedBinaries...),
		EnforcementEnabled:       enabled,
		ToggleFile:               b.core.ToggleFile(),
	}
}

func (b *uiBackend) PolicyGet() (string, error) {
	policy := b.core.CurrentPolicy()
	payload, err := yaml.Marshal(policy)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func (b *uiBackend) PolicySet(yamlText string) error {
	if !b.allowWrite {
		return uiapi.ErrPolicyWriteDisabled
	}
	var policy Policy
	if err := yaml.Unmarshal([]byte(yamlText), &policy); err != nil {
		return fmt.Errorf("%w: %v", uiapi.ErrInvalidPolicy, err)
	}
	b.core.UpdatePolicy(policy)
	b.addHistory("update", policy, yamlText)
	if b.policyPath != "" {
		if err := os.WriteFile(b.policyPath, []byte(yamlText), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (b *uiBackend) Templates() []uiapi.Template {
	templates := PolicyTemplates()
	out := make([]uiapi.Template, 0, len(templates))
	for _, tpl := range templates {
		out = append(out, uiapi.Template{
			ID:          tpl.ID,
			Name:        tpl.Name,
			Description: tpl.Description,
			YAML:        tpl.YAML,
		})
	}
	return out
}

func (b *uiBackend) ToggleGet() (bool, string) {
	return b.core.Enabled(), b.core.ToggleFile()
}

func (b *uiBackend) ToggleSet(enabled bool) error {
	if b.core.ToggleFile() == "" {
		return uiapi.ErrToggleUnsupported
	}
	return b.core.SetEnabled(enabled)
}

func (b *uiBackend) Help() uiapi.Help {
	help := PolicyHelpText()
	return uiapi.Help{Schema: help.Schema, Notes: help.Notes}
}

func (b *uiBackend) HistoryList(limit int) (string, []uiapi.HistoryEntry) {
	if b.history == nil {
		return "", nil
	}
	current, snaps := b.history.List(limit)
	entries := make([]uiapi.HistoryEntry, 0, len(snaps))
	for i := len(snaps) - 1; i >= 0; i-- {
		snap := snaps[i]
		entries = append(entries, uiapi.HistoryEntry{
			ID:        snap.ID,
			TS:        snap.TS,
			Reason:    snap.Reason,
			Tools:     snap.Tools,
			Resources: snap.Resources,
			Prompts:   snap.Prompts,
		})
	}
	return current, entries
}

func (b *uiBackend) HistoryGet(id string) (string, error) {
	if b.history == nil {
		return "", uiapi.ErrHistoryDisabled
	}
	snap, ok := b.history.Get(id)
	if !ok {
		return "", uiapi.ErrHistoryNotFound
	}
	if snap.YAML == "" {
		if data, err := yaml.Marshal(snap.Policy); err == nil {
			snap.YAML = string(data)
		}
	}
	return snap.YAML, nil
}

func (b *uiBackend) HistoryRollback(id string) error {
	if !b.allowWrite {
		return uiapi.ErrPolicyWriteDisabled
	}
	if b.history == nil {
		return uiapi.ErrHistoryDisabled
	}
	snap, ok := b.history.Get(id)
	if !ok {
		return uiapi.ErrHistoryNotFound
	}
	b.core.UpdatePolicy(snap.Policy)
	b.addHistory("rollback:"+id, snap.Policy, snap.YAML)
	if b.policyPath != "" {
		if err := os.WriteFile(b.policyPath, []byte(snap.YAML), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (b *uiBackend) Simulate(policyYAML string, event uiapi.SimulateEvent) (uiapi.SimulateResult, error) {
	var policy Policy
	if err := yaml.Unmarshal([]byte(policyYAML), &policy); err != nil {
		return uiapi.SimulateResult{}, fmt.Errorf("%w: %v", uiapi.ErrInvalidPolicy, err)
	}
	return simulateEvent(policy, event), nil
}

func (b *uiBackend) RecentLogs(limit int) []json.RawMessage {
	if b.logger == nil {
		return nil
	}
	events := b.logger.Recent(limit)
	payloads := make([]json.RawMessage, 0, len(events))
	for _, event := range events {
		if data, err := json.Marshal(event); err == nil {
			payloads = append(payloads, data)
		}
	}
	return payloads
}

func (b *uiBackend) SubscribeLogs(buffer int) (<-chan json.RawMessage, func()) {
	if b.logger == nil {
		ch := make(chan json.RawMessage)
		close(ch)
		return ch, func() {}
	}
	logCh, cancel := b.logger.Subscribe(buffer)
	out := make(chan json.RawMessage, buffer)
	go func() {
		for event := range logCh {
			if data, err := json.Marshal(event); err == nil {
				select {
				case out <- data:
				default:
				}
			}
		}
		close(out)
	}()
	return out, cancel
}

func (b *uiBackend) bootstrapHistory() {
	if b.history == nil {
		return
	}
	policy := b.core.CurrentPolicy()
	yamlText := ""
	if b.policyPath != "" {
		if data, err := os.ReadFile(b.policyPath); err == nil {
			yamlText = string(data)
		}
	}
	if yamlText == "" {
		if data, err := yaml.Marshal(policy); err == nil {
			yamlText = string(data)
		}
	}
	b.addHistory("startup", policy, yamlText)
}

func (b *uiBackend) addHistory(reason string, policy Policy, yamlText string) {
	if b.history == nil {
		return
	}
	b.history.Add(reason, policy, yamlText)
}

func simulateEvent(policy Policy, event uiapi.SimulateEvent) uiapi.SimulateResult {
	result := uiapi.SimulateResult{
		Method: event.Method,
		Name:   event.Name,
		URI:    event.URI,
	}
	allowedMethod, reason, match := policy.Methods.AllowedMatch(event.Method)
	methodRule := "methods"
	if match.Rule != "" {
		methodRule = "methods." + match.Rule
	}
	if !allowedMethod {
		result.Decision = "blocked"
		result.Reason = reason
		result.PolicyRule = methodRule
		result.PolicyPattern = match.Pattern
		return result
	}

	switch event.Method {
	case "tools/call":
		if event.Name == "" {
			result.Decision = "allowed"
			result.Reason = "tool name missing (method allowed)"
			result.PolicyRule = methodRule
			result.PolicyPattern = match.Pattern
			return result
		}
		allowed, toolReason, toolMatch := policy.Tools.AllowedMatch(event.Name)
		normalized := event.Name
		if policy.Tools.CaseInsensitive {
			normalized = strings.ToLower(normalized)
		}
		result.Normalized = normalized
		result.PolicyRule = "tools." + toolMatch.Rule
		result.PolicyPattern = toolMatch.Pattern
		if !allowed {
			result.Decision = "blocked"
			result.Reason = toolReason
			return result
		}
		result.Decision = "allowed"
		return result
	case "resources/read":
		if event.URI == "" {
			result.Decision = "allowed"
			result.Reason = "resource uri missing (method allowed)"
			result.PolicyRule = methodRule
			result.PolicyPattern = match.Pattern
			return result
		}
		allowed, resReason, resMatch := policy.Resources.AllowedMatch(event.URI)
		result.Normalized = normalizeResourceURI(event.URI, policy.Resources.Normalize)
		result.PolicyRule = "resources." + resMatch.Rule
		result.PolicyPattern = resMatch.Pattern
		if !allowed {
			result.Decision = "blocked"
			result.Reason = resReason
			return result
		}
		result.Decision = "allowed"
		return result
	case "prompts/get":
		if event.Name == "" {
			result.Decision = "allowed"
			result.Reason = "prompt name missing (method allowed)"
			result.PolicyRule = methodRule
			result.PolicyPattern = match.Pattern
			return result
		}
		allowed, promptReason, promptMatch := policy.Prompts.AllowedMatch(event.Name)
		normalized := event.Name
		if policy.Prompts.CaseInsensitive {
			normalized = strings.ToLower(normalized)
		}
		result.Normalized = normalized
		result.PolicyRule = "prompts." + promptMatch.Rule
		result.PolicyPattern = promptMatch.Pattern
		if !allowed {
			result.Decision = "blocked"
			result.Reason = promptReason
			return result
		}
		result.Decision = "allowed"
		return result
	default:
		result.Decision = "allowed"
		result.Reason = "method allowed"
		result.PolicyRule = methodRule
		result.PolicyPattern = match.Pattern
		return result
	}
}
