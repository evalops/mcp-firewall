package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type Proxy struct {
	policyMu sync.RWMutex
	policy   Policy
	logger   *Logger
	dryRun   bool
	inspect  InspectorConfig
	sandbox  SandboxConfig
	toggle   ToggleConfig

	pendingMu sync.Mutex
	pending   map[string]pendingRequest
}

type ProxyOptions struct {
	Logger  *Logger
	DryRun  bool
	Inspect InspectorConfig
	Sandbox SandboxConfig
	Toggle  ToggleConfig
}

func NewProxy(policy Policy, opts ProxyOptions) *Proxy {
	return &Proxy{
		policy:  policy,
		logger:  opts.Logger,
		dryRun:  opts.DryRun,
		inspect: opts.Inspect,
		sandbox: opts.Sandbox,
		toggle:  opts.Toggle,
		pending: make(map[string]pendingRequest),
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
		p.logger.Log(LogEvent{
			Direction: "client->server",
			Decision:  decision,
			Reason:    reason,
			Method:    msg.Method,
			ID:        normalizeID(msg.ID),
			Name:      detail.name,
			URI:       detail.uri,
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
			allowed, reason := policy.Methods.Allowed(msg.Method)
			decision := "allowed"
			if !allowed {
				if p.dryRun {
					decision = "would_block"
				} else {
					decision = "blocked"
				}
			}
			p.logger.Log(LogEvent{
				Direction: "server->client",
				Decision:  decision,
				Reason:    reason,
				Method:    msg.Method,
				ID:        normalizeID(msg.ID),
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
			if p.inspect.enabled() && outcome.inspection.Score >= p.inspect.Threshold {
				p.logger.Log(LogEvent{
					Direction: "server->client",
					Decision:  "flagged",
					Reason:    outcome.reason,
					Method:    pending.method,
					ID:        normalizeID(msg.ID),
					Name:      pending.name,
					URI:       pending.uri,
					Score:     outcome.inspection.Score,
					Flags:     outcome.inspection.Flags,
					Excerpt:   outcome.inspection.Excerpt,
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
	if allowed, reason := policy.Methods.Allowed(method); !allowed {
		return false, reason, pendingRequest{}
	}

	switch method {
	case "tools/call":
		var parsed toolCallParams
		if err := json.Unmarshal(params, &parsed); err != nil {
			return true, "", pendingRequest{method: method}
		}
		allowed, reason := policy.Tools.Allowed(parsed.Name)
		return allowed, reason, pendingRequest{method: method, name: parsed.Name}
	case "resources/read":
		var parsed resourceReadParams
		if err := json.Unmarshal(params, &parsed); err != nil {
			return true, "", pendingRequest{method: method}
		}
		allowed, reason := policy.Resources.Allowed(parsed.URI)
		return allowed, reason, pendingRequest{method: method, uri: parsed.URI}
	case "prompts/get":
		var parsed promptGetParams
		if err := json.Unmarshal(params, &parsed); err != nil {
			return true, "", pendingRequest{method: method}
		}
		allowed, reason := policy.Prompts.Allowed(parsed.Name)
		return allowed, reason, pendingRequest{method: method, name: parsed.Name}
	default:
		return true, "", pendingRequest{method: method}
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
	trimmed := string(id)
	if trimmed == "null" {
		return ""
	}
	return trimmed
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

func (p *Proxy) Sandbox() SandboxConfig {
	return p.sandbox
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
