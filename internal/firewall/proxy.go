package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

type Proxy struct {
	policyMu        sync.RWMutex
	policy          Policy
	logger          *Logger
	dryRun          bool
	enforcementMode string
	inspect         InspectorConfig
	sandbox         SandboxConfig
	toggle          ToggleConfig

	pendingMu sync.Mutex
	pending   map[string]pendingRequest
	reqSeq    uint64
}

type ProxyOptions struct {
	Logger  *Logger
	DryRun  bool
	Mode    string
	Inspect InspectorConfig
	Sandbox SandboxConfig
	Toggle  ToggleConfig
}

func NewProxy(policy Policy, opts ProxyOptions) *Proxy {
	return &Proxy{
		policy:          policy,
		logger:          opts.Logger,
		dryRun:          opts.DryRun,
		enforcementMode: opts.Mode,
		inspect:         opts.Inspect,
		sandbox:         opts.Sandbox,
		toggle:          opts.Toggle,
		pending:         make(map[string]pendingRequest),
	}
}

type RunConfig struct {
	Command       []string
	ClientFraming FramingMode
	ServerFraming FramingMode
	Sandbox       SandboxConfig
}

func (p *Proxy) Run(ctx context.Context, clientR io.Reader, clientW io.Writer, cfg RunConfig) error {
	cmd, err := newServerCommand(ctx, cfg.Command, cfg.Sandbox)
	if err != nil {
		return err
	}
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	clientCodec := NewCodec(clientR, clientW, cfg.ClientFraming)
	serverCodec := NewCodec(serverOut, serverIn, cfg.ServerFraming)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() {
		errCh <- p.forwardClientToServer(ctx, clientCodec, serverCodec)
	}()
	go func() {
		errCh <- p.forwardServerToClient(ctx, serverCodec, clientCodec)
	}()

	err = <-errCh
	cancel()
	_ = serverIn.Close()
	_ = serverOut.Close()
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	<-errCh
	_ = cmd.Wait()
	return err
}

func (p *Proxy) forwardClientToServer(ctx context.Context, client *Codec, server *Codec) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		msgBytes, err := client.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var msg rpcMessage
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			// If we cannot parse, allow pass-through.
			if err := server.WriteMessage(msgBytes); err != nil {
				return err
			}
			continue
		}

		if msg.Method == "" {
			// Responses from client are unexpected; pass through.
			if err := server.WriteMessage(msgBytes); err != nil {
				return err
			}
			continue
		}

		allowed, reason, detail := p.evaluateRequest(msg.Method, msg.Params)
		decision := "allowed"
		if !allowed {
			if p.dryRun {
				decision = "would_block"
			} else {
				decision = "blocked"
			}
		}
		requestID, traceID, rpcID := p.newRequestIDs(msg.ID)
		detail.requestID = requestID
		detail.traceID = traceID
		p.logger.Log(LogEvent{
			Direction:     "client->server",
			Decision:      decision,
			Reason:        reason,
			Method:        msg.Method,
			ID:            rpcID,
			RequestID:     requestID,
			TraceID:       traceID,
			Name:          detail.name,
			URI:           detail.uri,
			Normalized:    detail.normalized,
			PolicyRule:    detail.rule,
			PolicyPattern: detail.pattern,
		})

		if !allowed && !p.dryRun {
			if hasID(msg.ID) {
				errResp := blockedResponse(msg.ID, reason)
				if err := client.WriteMessage(errResp); err != nil {
					return err
				}
			}
			continue
		}

		if hasID(msg.ID) {
			p.storePending(msg.ID, detail)
		}
		if err := server.WriteMessage(msgBytes); err != nil {
			return err
		}
	}
}

func (p *Proxy) forwardServerToClient(ctx context.Context, server *Codec, client *Codec) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		msgBytes, err := server.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var msg rpcMessage
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			if err := client.WriteMessage(msgBytes); err != nil {
				return err
			}
			continue
		}

		if msg.Method != "" {
			if !p.Enabled() {
				if err := client.WriteMessage(msgBytes); err != nil {
					return err
				}
				continue
			}
			policy := p.currentPolicy()
			allowed, reason, match := policy.Methods.AllowedMatch(msg.Method)
			decision := "allowed"
			if !allowed {
				if p.dryRun {
					decision = "would_block"
				} else {
					decision = "blocked"
				}
			}
			requestID, traceID, rpcID := p.newRequestIDs(msg.ID)
			methodRule := "methods"
			if match.Rule != "" {
				methodRule = "methods." + match.Rule
			}
			p.logger.Log(LogEvent{
				Direction:     "server->client",
				Decision:      decision,
				Reason:        reason,
				Method:        msg.Method,
				ID:            rpcID,
				RequestID:     requestID,
				TraceID:       traceID,
				PolicyRule:    methodRule,
				PolicyPattern: match.Pattern,
			})
			if !allowed && !p.dryRun {
				if hasID(msg.ID) {
					errResp := blockedResponse(msg.ID, reason)
					if err := server.WriteMessage(errResp); err != nil {
						return err
					}
				}
				continue
			}
			if err := client.WriteMessage(msgBytes); err != nil {
				return err
			}
			continue
		}

		pending := p.loadPending(normalizeID(msg.ID))
		if pending.method != "" {
			outcome, err := p.processResponse(pending, &msg)
			if err != nil {
				return err
			}
			if outcome.threshold > 0 && outcome.inspection.Score >= outcome.threshold {
				reqID := normalizeID(msg.ID)
				requestID := pending.requestID
				traceID := pending.traceID
				if requestID == "" {
					requestID = reqID
				}
				if traceID == "" {
					if reqID != "" {
						traceID = reqID
					} else {
						traceID = requestID
					}
				}
				p.logger.Log(LogEvent{
					Direction:     "server->client",
					Decision:      "flagged",
					Reason:        outcome.reason,
					Method:        pending.method,
					ID:            reqID,
					RequestID:     requestID,
					TraceID:       traceID,
					Name:          pending.name,
					URI:           pending.uri,
					Normalized:    pending.normalized,
					PolicyRule:    pending.rule,
					PolicyPattern: pending.pattern,
					Score:         outcome.inspection.Score,
					Flags:         outcome.inspection.Flags,
					Excerpt:       outcome.inspection.Excerpt,
				})
			}
			if outcome.blocked && !p.dryRun {
				if hasID(msg.ID) {
					errResp := blockedResponse(msg.ID, outcome.reason)
					if err := client.WriteMessage(errResp); err != nil {
						return err
					}
				}
				continue
			}
			if outcome.modified {
				updated, err := json.Marshal(msg)
				if err == nil {
					msgBytes = updated
				}
			}
		}

		if err := client.WriteMessage(msgBytes); err != nil {
			return err
		}
	}
}

func (p *Proxy) evaluateRequest(method string, params json.RawMessage) (bool, string, pendingRequest) {
	if !p.Enabled() {
		return true, "firewall disabled", pendingRequest{method: method}
	}
	policy := p.currentPolicy()
	allowedMethod, reason, match := policy.Methods.AllowedMatch(method)
	methodRule := "methods." + match.Rule
	if methodRule == "methods." {
		methodRule = "methods"
	}
	if !allowedMethod {
		return false, reason, pendingRequest{method: method, rule: methodRule, pattern: match.Pattern}
	}

	switch method {
	case "tools/call":
		var parsed toolCallParams
		if err := json.Unmarshal(params, &parsed); err != nil {
			return true, "", pendingRequest{method: method, rule: methodRule, pattern: match.Pattern}
		}
		allowed, reason, toolMatch := policy.Tools.AllowedMatch(parsed.Name)
		normalized := parsed.Name
		if policy.Tools.CaseInsensitive {
			normalized = strings.ToLower(normalized)
		}
		return allowed, reason, pendingRequest{
			method:     method,
			name:       parsed.Name,
			normalized: normalized,
			rule:       "tools." + toolMatch.Rule,
			pattern:    toolMatch.Pattern,
		}
	case "resources/read":
		var parsed resourceReadParams
		if err := json.Unmarshal(params, &parsed); err != nil {
			return true, "", pendingRequest{method: method, rule: methodRule, pattern: match.Pattern}
		}
		allowed, reason, resourceMatch := policy.Resources.AllowedMatch(parsed.URI)
		normalized := normalizeResourceURI(parsed.URI, policy.Resources.Normalize)
		return allowed, reason, pendingRequest{
			method:     method,
			uri:        parsed.URI,
			scheme:     schemeOf(normalized),
			normalized: normalized,
			rule:       "resources." + resourceMatch.Rule,
			pattern:    resourceMatch.Pattern,
		}
	case "prompts/get":
		var parsed promptGetParams
		if err := json.Unmarshal(params, &parsed); err != nil {
			return true, "", pendingRequest{method: method, rule: methodRule, pattern: match.Pattern}
		}
		allowed, reason, promptMatch := policy.Prompts.AllowedMatch(parsed.Name)
		normalized := parsed.Name
		if policy.Prompts.CaseInsensitive {
			normalized = strings.ToLower(normalized)
		}
		return allowed, reason, pendingRequest{
			method:     method,
			name:       parsed.Name,
			normalized: normalized,
			rule:       "prompts." + promptMatch.Rule,
			pattern:    promptMatch.Pattern,
		}
	default:
		return true, "", pendingRequest{method: method, rule: methodRule, pattern: match.Pattern}
	}
}

func (p *Proxy) storePending(id json.RawMessage, detail pendingRequest) {
	key := normalizeID(id)
	if key == "" {
		return
	}
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	p.pending[key] = detail
}

func (p *Proxy) loadPending(id string) pendingRequest {
	if id == "" {
		return pendingRequest{}
	}
	p.pendingMu.Lock()
	defer p.pendingMu.Unlock()
	method, ok := p.pending[id]
	if ok {
		delete(p.pending, id)
		return method
	}
	return pendingRequest{}
}

func hasID(id json.RawMessage) bool {
	return normalizeID(id) != ""
}

func normalizeID(id json.RawMessage) string {
	if len(id) == 0 {
		return ""
	}
	trimmed := strings.TrimSpace(string(id))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	var str string
	if err := json.Unmarshal(id, &str); err == nil {
		return str
	}
	var num json.Number
	if err := json.Unmarshal(id, &num); err == nil {
		return num.String()
	}
	return trimmed
}

func (p *Proxy) nextRequestID() string {
	seq := atomic.AddUint64(&p.reqSeq, 1)
	return fmt.Sprintf("req-%08d", seq)
}

func (p *Proxy) newRequestIDs(id json.RawMessage) (string, string, string) {
	rpcID := normalizeID(id)
	requestID := p.nextRequestID()
	traceID := rpcID
	if traceID == "" {
		traceID = requestID
	}
	return requestID, traceID, rpcID
}

func blockedResponse(id json.RawMessage, reason string) []byte {
	resp := rpcMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error: &rpcError{
			Code:    -32000,
			Message: "Blocked by MCP firewall",
			Data: map[string]string{
				"reason": reason,
			},
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		fallback := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"Blocked by MCP firewall"}}`, id)
		return []byte(fallback)
	}
	return data
}

func (p *Proxy) currentPolicy() Policy {
	p.policyMu.RLock()
	defer p.policyMu.RUnlock()
	return p.policy
}

func (p *Proxy) UpdatePolicy(policy Policy) {
	p.policyMu.Lock()
	defer p.policyMu.Unlock()
	p.policy = policy
}

func (p *Proxy) CurrentPolicy() Policy {
	return p.currentPolicy()
}

func (p *Proxy) DryRun() bool {
	return p.dryRun
}

func (p *Proxy) InspectEnabled() bool {
	return p.inspect.enabled()
}

func (p *Proxy) InspectThreshold() int {
	return p.inspect.Threshold
}

func (p *Proxy) InspectToolThreshold() int {
	return p.inspect.ToolThreshold
}

func (p *Proxy) InspectResourceThreshold() int {
	return p.inspect.ResourceThreshold
}

func (p *Proxy) InspectPromptThreshold() int {
	return p.inspect.PromptThreshold
}

func (p *Proxy) Sandbox() SandboxConfig {
	return p.sandbox
}

func (p *Proxy) EnforcementMode() string {
	if p.enforcementMode != "" {
		return p.enforcementMode
	}
	if p.dryRun {
		return "observe"
	}
	return "enforce"
}

func (p *Proxy) Enabled() bool {
	if p.toggle.EnabledFile == "" {
		return true
	}
	_, err := os.Stat(p.toggle.EnabledFile)
	return err == nil
}

func (p *Proxy) ToggleFile() string {
	return p.toggle.EnabledFile
}

func (p *Proxy) SetEnabled(value bool) error {
	if p.toggle.EnabledFile == "" {
		return ErrToggleUnsupported
	}
	if value {
		if err := os.MkdirAll(filepath.Dir(p.toggle.EnabledFile), 0o700); err != nil {
			return err
		}
		return os.WriteFile(p.toggle.EnabledFile, []byte("enabled\n"), 0o600)
	}
	if err := os.Remove(p.toggle.EnabledFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
