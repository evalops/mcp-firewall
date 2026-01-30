package firewall

import (
	"sync"
	"time"
)

type PolicySnapshot struct {
	ID        string
	TS        string
	Reason    string
	Tools     int
	Resources int
	Prompts   int
	Policy    Policy
	YAML      string
}

type PolicyHistory struct {
	mu       sync.Mutex
	limit    int
	seq      uint64
	current  string
	snapshot []PolicySnapshot
}

func NewPolicyHistory(limit int) *PolicyHistory {
	if limit <= 0 {
		limit = 20
	}
	return &PolicyHistory{limit: limit}
}

func (h *PolicyHistory) Add(reason string, policy Policy, yamlText string) PolicySnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	id := ts + "-" + formatUint(h.seq)
	snap := PolicySnapshot{
		ID:        id,
		TS:        ts,
		Reason:    reason,
		Tools:     len(policy.Tools.Allow),
		Resources: len(policy.Resources.Allow),
		Prompts:   len(policy.Prompts.Allow),
		Policy:    policy,
		YAML:      yamlText,
	}
	h.snapshot = append(h.snapshot, snap)
	if len(h.snapshot) > h.limit {
		h.snapshot = append(h.snapshot[:0], h.snapshot[len(h.snapshot)-h.limit:]...)
	}
	h.current = id
	return snap
}

func (h *PolicyHistory) List(limit int) (string, []PolicySnapshot) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if limit <= 0 || limit > len(h.snapshot) {
		limit = len(h.snapshot)
	}
	start := len(h.snapshot) - limit
	out := make([]PolicySnapshot, 0, limit)
	out = append(out, h.snapshot[start:]...)
	return h.current, out
}

func (h *PolicyHistory) Get(id string) (PolicySnapshot, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, snap := range h.snapshot {
		if snap.ID == id {
			return snap, true
		}
	}
	return PolicySnapshot{}, false
}

func formatUint(value uint64) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	for value > 0 {
		rem := value % 10
		buf = append(buf, digits[rem])
		value = value / 10
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
