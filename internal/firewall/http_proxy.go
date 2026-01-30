package firewall

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	errRouteNotFound   = errors.New("route not found")
	errUpstreamMissing = errors.New("upstream not configured")
)

type HTTPProxy struct {
	core          *Proxy
	upstream      *url.URL
	routes        map[string]*url.URL
	allowOrigins  []string
	path          string
	uiPrefix      string
	maxBodyBytes  int64
	client        *http.Client
	forwardHeader []string
	uiHandler     http.Handler
	apiHandler    http.Handler
}

type HTTPProxyConfig struct {
	Upstream         *url.URL
	Routes           map[string]*url.URL
	AllowOrigins     []string
	Path             string
	UIPrefix         string
	PolicyPath       string
	AllowPolicyWrite bool
	APIToken         string
	PolicyHistory    int
	MaxBodyBytes     int64
}

func NewHTTPProxy(core *Proxy, cfg HTTPProxyConfig) *HTTPProxy {
	path := cfg.Path
	if path == "" {
		path = "/mcp"
	}
	uiPrefix := cfg.UIPrefix
	if uiPrefix == "" {
		uiPrefix = "/ui"
	}
	maxBody := cfg.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 20 << 20
	}
	client := &http.Client{
		Timeout: 0,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	proxy := &HTTPProxy{
		core:         core,
		upstream:     cfg.Upstream,
		routes:       cfg.Routes,
		allowOrigins: cfg.AllowOrigins,
		path:         path,
		maxBodyBytes: maxBody,
		client:       client,
		forwardHeader: []string{
			"accept",
			"authorization",
			"cookie",
			"mcp-session-id",
			"mcp-protocol-version",
			"user-agent",
		},
		uiPrefix:   uiPrefix,
		uiHandler:  initUIHandler(),
		apiHandler: newAPIHandler(core, cfg, maxBody),
	}
	return proxy
}

func (p *HTTPProxy) handleGET(w http.ResponseWriter, r *http.Request) {
	upstream, err := p.pickUpstream(r)
	if err != nil {
		p.writeUpstreamError(w, err)
		return
	}
	req, err := p.newUpstreamRequest(r.Context(), http.MethodGet, nil, r, upstream)
	if err != nil {
		http.Error(w, "bad upstream", http.StatusBadGateway)
		return
	}
	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	if isEventStream(resp.Header.Get("Content-Type")) {
		p.pipeSSE(w, resp.Body, pendingRequest{}, "")
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func (p *HTTPProxy) handlePOST(w http.ResponseWriter, r *http.Request) {
	upstream, err := p.pickUpstream(r)
	if err != nil {
		p.writeUpstreamError(w, err)
		return
	}
	body, err := readLimited(r.Body, p.maxBodyBytes)
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(body, &msg); err == nil && msg.Method != "" {
		allowed, reason, detail := p.core.evaluateRequest(msg.Method, msg.Params)
		decision := "allowed"
		if !allowed {
			if p.core.dryRun {
				decision = "would_block"
			} else {
				decision = "blocked"
			}
		}
		requestID, traceID, rpcID := p.core.newRequestIDs(msg.ID)
		detail.requestID = requestID
		detail.traceID = traceID
		p.core.logger.Log(LogEvent{
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
		if !allowed && !p.core.dryRun {
			if hasID(msg.ID) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(blockedResponse(msg.ID, reason))
			} else {
				http.Error(w, "blocked by MCP firewall", http.StatusForbidden)
			}
			return
		}

		req, err := p.newUpstreamRequest(r.Context(), http.MethodPost, bytes.NewReader(body), r, upstream)
		if err != nil {
			http.Error(w, "bad upstream", http.StatusBadGateway)
			return
		}
		resp, err := p.client.Do(req)
		if err != nil {
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		p.copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)

		if isEventStream(resp.Header.Get("Content-Type")) {
			p.pipeSSE(w, resp.Body, detail, normalizeID(msg.ID))
			return
		}

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}
		var respMsg rpcMessage
		if err := json.Unmarshal(respBody, &respMsg); err == nil {
			outcome, err := p.core.processResponse(detail, &respMsg)
			if err == nil {
				if outcome.threshold > 0 && outcome.inspection.Score >= outcome.threshold {
					reqID := normalizeID(respMsg.ID)
					requestID := detail.requestID
					traceID := detail.traceID
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
					p.core.logger.Log(LogEvent{
						Direction:     "server->client",
						Decision:      "flagged",
						Reason:        outcome.reason,
						Method:        detail.method,
						ID:            reqID,
						RequestID:     requestID,
						TraceID:       traceID,
						Name:          detail.name,
						URI:           detail.uri,
						Normalized:    detail.normalized,
						PolicyRule:    detail.rule,
						PolicyPattern: detail.pattern,
						Score:         outcome.inspection.Score,
						Flags:         outcome.inspection.Flags,
						Excerpt:       outcome.inspection.Excerpt,
					})
				}
				if outcome.blocked && !p.core.dryRun {
					if hasID(respMsg.ID) {
						_, _ = w.Write(blockedResponse(respMsg.ID, outcome.reason))
					} else {
						http.Error(w, "blocked by MCP firewall", http.StatusForbidden)
					}
					return
				}
				if outcome.modified {
					if updated, err := json.Marshal(respMsg); err == nil {
						respBody = updated
					}
				}
			}
		}
		_, _ = w.Write(respBody)
		return
	}

	req, err := p.newUpstreamRequest(r.Context(), http.MethodPost, bytes.NewReader(body), r, upstream)
	if err != nil {
		http.Error(w, "bad upstream", http.StatusBadGateway)
		return
	}
	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	p.copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *HTTPProxy) handleDELETE(w http.ResponseWriter, r *http.Request) {
	upstream, err := p.pickUpstream(r)
	if err != nil {
		p.writeUpstreamError(w, err)
		return
	}
	req, err := p.newUpstreamRequest(r.Context(), http.MethodDelete, nil, r, upstream)
	if err != nil {
		http.Error(w, "bad upstream", http.StatusBadGateway)
		return
	}
	resp, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	p.copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *HTTPProxy) newUpstreamRequest(ctx context.Context, method string, body io.Reader, in *http.Request, upstream *url.URL) (*http.Request, error) {
	if upstream == nil {
		return nil, errors.New("missing upstream")
	}
	target := *upstream
	req, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, err
	}
	req.URL.RawQuery = in.URL.RawQuery
	for _, key := range p.forwardHeader {
		if val := in.Header.Get(key); val != "" {
			req.Header.Set(key, val)
		}
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (p *HTTPProxy) matchesMCPPath(path string) bool {
	if len(p.routes) == 0 {
		return path == p.path
	}
	base := strings.TrimSuffix(p.path, "/")
	return strings.HasPrefix(path, base+"/")
}

func (p *HTTPProxy) pickUpstream(r *http.Request) (*url.URL, error) {
	if len(p.routes) == 0 {
		if p.upstream == nil {
			return nil, errUpstreamMissing
		}
		return p.upstream, nil
	}
	base := strings.TrimSuffix(p.path, "/")
	prefix := base + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return nil, errRouteNotFound
	}
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		return nil, errRouteNotFound
	}
	upstream := p.routes[parts[0]]
	if upstream == nil {
		return nil, errRouteNotFound
	}
	return upstream, nil
}

func (p *HTTPProxy) writeUpstreamError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errRouteNotFound):
		http.Error(w, "unknown route", http.StatusNotFound)
	case errors.Is(err, errUpstreamMissing):
		http.Error(w, "upstream not configured", http.StatusServiceUnavailable)
	default:
		http.Error(w, "bad upstream", http.StatusBadGateway)
	}
}

func (p *HTTPProxy) copyHeaders(dst http.Header, src http.Header) {
	for key, values := range src {
		switch strings.ToLower(key) {
		case "content-length", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
			continue
		default:
			for _, value := range values {
				dst.Add(key, value)
			}
		}
	}
}

func (p *HTTPProxy) pipeSSE(w http.ResponseWriter, body io.Reader, pending pendingRequest, expectedID string) {
	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(body)
	for {
		event, err := readSSEEvent(reader)
		if err != nil {
			if err == io.EOF {
				return
			}
			return
		}
		if event.Data != "" {
			var msg rpcMessage
			if err := json.Unmarshal([]byte(event.Data), &msg); err == nil {
				if msg.Method != "" {
					if !p.core.Enabled() {
						goto writeEvent
					}
					policy := p.core.currentPolicy()
					allowed, reason, match := policy.Methods.AllowedMatch(msg.Method)
					decision := "allowed"
					if !allowed {
						if p.core.dryRun {
							decision = "would_block"
						} else {
							decision = "blocked"
						}
					}
					requestID, traceID, rpcID := p.core.newRequestIDs(msg.ID)
					methodRule := "methods"
					if match.Rule != "" {
						methodRule = "methods." + match.Rule
					}
					p.core.logger.Log(LogEvent{
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
					if !allowed && !p.core.dryRun {
						continue
					}
				} else if pending.method != "" {
					if expectedID != "" && normalizeID(msg.ID) != expectedID {
						// Not the response we are tracking; pass through.
						goto writeEvent
					}
					outcome, err := p.core.processResponse(pending, &msg)
					if err == nil {
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
							p.core.logger.Log(LogEvent{
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
						if outcome.blocked && !p.core.dryRun {
							if hasID(msg.ID) {
								event.Data = string(blockedResponse(msg.ID, outcome.reason))
							} else {
								continue
							}
						}
						if outcome.modified {
							if updated, err := json.Marshal(msg); err == nil {
								event.Data = string(updated)
							}
						}
					}
				}
			}
		}
	writeEvent:
		_ = writeSSEEvent(w, event)
		if flusher != nil {
			flusher.Flush()
		}
	}
}

func isEventStream(contentType string) bool {
	return strings.HasPrefix(strings.ToLower(contentType), "text/event-stream")
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		return io.ReadAll(r)
	}
	lr := &io.LimitedReader{R: r, N: max + 1}
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("payload exceeds limit")
	}
	return data, nil
}
