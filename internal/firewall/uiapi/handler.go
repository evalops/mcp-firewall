package uiapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

var (
	ErrPolicyWriteDisabled = errors.New("policy write disabled")
	ErrInvalidPolicy       = errors.New("invalid policy")
	ErrHistoryDisabled     = errors.New("policy history disabled")
	ErrHistoryNotFound     = errors.New("history entry not found")
	ErrToggleUnsupported   = errors.New("toggle unsupported")
)

type Status struct {
	Ready              bool     `json:"ready"`
	Mode               string   `json:"mode"`
	Upstream           string   `json:"upstream"`
	DryRun             bool     `json:"dryRun"`
	InspectEnabled     bool     `json:"inspectEnabled"`
	InspectThreshold   int      `json:"inspectThreshold"`
	Tools              int      `json:"tools"`
	Resources          int      `json:"resources"`
	Prompts            int      `json:"prompts"`
	PolicyWritable     bool     `json:"policyWritable"`
	PolicyVersion      string   `json:"policyVersion"`
	NoNetwork          bool     `json:"noNetwork"`
	SandboxBestEffort  bool     `json:"sandboxBestEffort"`
	AllowedBins        []string `json:"allowedBins,omitempty"`
	EnforcementEnabled bool     `json:"enforcementEnabled"`
	ToggleFile         string   `json:"toggleFile,omitempty"`
}

type HistoryEntry struct {
	ID        string `json:"id"`
	TS        string `json:"ts"`
	Reason    string `json:"reason"`
	Tools     int    `json:"tools"`
	Resources int    `json:"resources"`
	Prompts   int    `json:"prompts"`
}

type Template struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	YAML        string `json:"yaml"`
}

type Help struct {
	Schema string   `json:"schema"`
	Notes  []string `json:"notes"`
}

type Backend interface {
	Status() Status
	PolicyGet() (string, error)
	PolicySet(yamlText string) error
	Templates() []Template
	Help() Help
	HistoryList(limit int) (string, []HistoryEntry)
	HistoryGet(id string) (string, error)
	HistoryRollback(id string) error
	RecentLogs(limit int) []json.RawMessage
	SubscribeLogs(buffer int) (<-chan json.RawMessage, func())
	ToggleGet() (bool, string)
	ToggleSet(enabled bool) error
}

type Config struct {
	Backend     Backend
	APIToken    string
	MaxBodySize int64
}

type Handler struct {
	backend  Backend
	apiToken string
	maxBody  int64
}

func NewHandler(cfg Config) *Handler {
	maxBody := cfg.MaxBodySize
	if maxBody <= 0 {
		maxBody = 20 << 20
	}
	return &Handler{
		backend:  cfg.Backend,
		apiToken: cfg.APIToken,
		maxBody:  maxBody,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/api/status":
		h.handleStatus(w, r)
	case r.URL.Path == "/api/policy":
		h.handlePolicy(w, r)
	case r.URL.Path == "/api/policy/templates":
		h.handleTemplates(w, r)
	case r.URL.Path == "/api/policy/help":
		h.handleHelp(w, r)
	case r.URL.Path == "/api/policy/rollback":
		h.handlePolicyRollback(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/policy/history"):
		h.handlePolicyHistory(w, r)
	case r.URL.Path == "/api/toggle":
		h.handleToggle(w, r)
	case r.URL.Path == "/api/logs/stream":
		h.handleLogsStream(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, h.backend.Status())
}

func (h *Handler) handlePolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		payload, err := h.backend.PolicyGet()
		if err != nil {
			http.Error(w, "failed to encode policy", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
		_, _ = w.Write([]byte(payload))
	case http.MethodPost:
		body, err := readLimited(r.Body, h.maxBody)
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		if err := h.backend.PolicySet(string(body)); err != nil {
			switch {
			case errors.Is(err, ErrPolicyWriteDisabled):
				http.Error(w, "policy write disabled", http.StatusForbidden)
			case errors.Is(err, ErrInvalidPolicy):
				http.Error(w, err.Error(), http.StatusBadRequest)
			default:
				http.Error(w, "failed to update policy", http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{"templates": h.backend.Templates()})
}

func (h *Handler) handleHelp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, h.backend.Help())
}

func (h *Handler) handlePolicyHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/api/policy/history" || r.URL.Path == "/api/policy/history/" {
		limit := 20
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		current, entries := h.backend.HistoryList(limit)
		writeJSON(w, map[string]interface{}{
			"current":  current,
			"history":  entries,
			"total":    len(entries),
			"maxItems": limit,
		})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/policy/history/")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	payload, err := h.backend.HistoryGet(id)
	if err != nil {
		switch {
		case errors.Is(err, ErrHistoryDisabled):
			http.Error(w, "policy history disabled", http.StatusBadRequest)
		case errors.Is(err, ErrHistoryNotFound):
			http.Error(w, "history entry not found", http.StatusNotFound)
		default:
			http.Error(w, "failed to load history", http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	_, _ = w.Write([]byte(payload))
}

func (h *Handler) handlePolicyRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := readLimited(r.Body, h.maxBody)
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	payload := struct {
		ID string `json:"id"`
	}{}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if payload.ID == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if err := h.backend.HistoryRollback(payload.ID); err != nil {
		switch {
		case errors.Is(err, ErrPolicyWriteDisabled):
			http.Error(w, "policy write disabled", http.StatusForbidden)
		case errors.Is(err, ErrHistoryDisabled):
			http.Error(w, "policy history disabled", http.StatusBadRequest)
		case errors.Is(err, ErrHistoryNotFound):
			http.Error(w, "history entry not found", http.StatusNotFound)
		default:
			http.Error(w, "failed to rollback policy", http.StatusInternalServerError)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleToggle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		enabled, file := h.backend.ToggleGet()
		writeJSON(w, map[string]interface{}{
			"enabled":    enabled,
			"toggleFile": file,
		})
	case http.MethodPost:
		body, err := readLimited(r.Body, h.maxBody)
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		payload := struct {
			Enabled bool `json:"enabled"`
		}{}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if err := h.backend.ToggleSet(payload.Enabled); err != nil {
			switch {
			case errors.Is(err, ErrToggleUnsupported):
				http.Error(w, "toggle not configured", http.StatusBadRequest)
			default:
				http.Error(w, "failed to update toggle", http.StatusInternalServerError)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleLogsStream(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	for _, event := range h.backend.RecentLogs(limit) {
		_ = writeSSE(w, "log", string(event))
	}
	flusher.Flush()

	ch, cancel := h.backend.SubscribeLogs(200)
	defer cancel()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			_ = writeSSE(w, "log", string(event))
			flusher.Flush()
		}
	}
}

func (h *Handler) authorize(r *http.Request) bool {
	if h.apiToken == "" {
		return true
	}
	if token := r.Header.Get("X-MCP-Firewall-Token"); token != "" {
		return token == h.apiToken
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			return strings.TrimSpace(auth[7:]) == h.apiToken
		}
	}
	if token := r.URL.Query().Get("token"); token != "" {
		return token == h.apiToken
	}
	return false
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
		return nil, errors.New("payload exceeds limit")
	}
	return data, nil
}

func writeJSON(w http.ResponseWriter, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(payload)
}

func writeSSE(w http.ResponseWriter, event, data string) error {
	if event != "" {
		if _, err := io.WriteString(w, "event: "+event+"\n"); err != nil {
			return err
		}
	}
	if data != "" {
		for _, line := range strings.Split(data, "\n") {
			if _, err := io.WriteString(w, "data: "+line+"\n"); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(w, "\n")
	return err
}
