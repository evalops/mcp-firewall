package firewall

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Logger struct {
	mu         sync.Mutex
	w          io.Writer
	logAllowed bool
	buffer     []LogEvent
	maxBuffer  int
	subs       map[chan LogEvent]struct{}
	seq        uint64
}

type LogEvent struct {
	Seq           uint64   `json:"seq,omitempty"`
	TS            string   `json:"ts"`
	Direction     string   `json:"direction"`
	Decision      string   `json:"decision"`
	Reason        string   `json:"reason,omitempty"`
	Method        string   `json:"method,omitempty"`
	ID            string   `json:"id,omitempty"`
	RequestID     string   `json:"requestId,omitempty"`
	TraceID       string   `json:"traceId,omitempty"`
	Name          string   `json:"name,omitempty"`
	URI           string   `json:"uri,omitempty"`
	Normalized    string   `json:"normalized,omitempty"`
	PolicyRule    string   `json:"policyRule,omitempty"`
	PolicyPattern string   `json:"policyPattern,omitempty"`
	Score         int      `json:"suspicionScore,omitempty"`
	Flags         []string `json:"suspicionFlags,omitempty"`
	Excerpt       string   `json:"suspicionExcerpt,omitempty"`
}

type LoggerOptions struct {
	LogAllowed bool
	MaxBuffer  int
}

func NewLogger(w io.Writer, logAllowed bool) *Logger {
	return NewLoggerWithOptions(w, LoggerOptions{LogAllowed: logAllowed, MaxBuffer: 1000})
}

func NewLoggerWithOptions(w io.Writer, opts LoggerOptions) *Logger {
	max := opts.MaxBuffer
	if max < 0 {
		max = 0
	}
	return &Logger{
		w:          w,
		logAllowed: opts.LogAllowed,
		maxBuffer:  max,
		buffer:     make([]LogEvent, 0, min(1000, max)),
		subs:       make(map[chan LogEvent]struct{}),
	}
}

func (l *Logger) Log(event LogEvent) {
	if l == nil || l.w == nil {
		return
	}
	if !l.logAllowed && event.Decision == "allowed" {
		return
	}
	if event.TS == "" {
		event.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	l.mu.Lock()
	l.seq++
	if event.Seq == 0 {
		event.Seq = l.seq
	}
	enc := json.NewEncoder(l.w)
	_ = enc.Encode(event)
	if l.maxBuffer > 0 {
		l.buffer = append(l.buffer, event)
		if len(l.buffer) > l.maxBuffer {
			trim := len(l.buffer) - l.maxBuffer
			l.buffer = append(l.buffer[:0], l.buffer[trim:]...)
		}
	}
	subs := make([]chan LogEvent, 0, len(l.subs))
	for ch := range l.subs {
		subs = append(subs, ch)
	}
	l.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- event:
		default:
		}
	}
}

func (l *Logger) Recent(limit int) []LogEvent {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit <= 0 || limit > len(l.buffer) {
		limit = len(l.buffer)
	}
	start := len(l.buffer) - limit
	out := make([]LogEvent, 0, limit)
	out = append(out, l.buffer[start:]...)
	return out
}

func (l *Logger) Subscribe(buffer int) (<-chan LogEvent, func()) {
	if l == nil {
		ch := make(chan LogEvent)
		close(ch)
		return ch, func() {}
	}
	if buffer < 0 {
		buffer = 0
	}
	ch := make(chan LogEvent, buffer)
	l.mu.Lock()
	l.subs[ch] = struct{}{}
	l.mu.Unlock()
	cancel := func() {
		l.mu.Lock()
		delete(l.subs, ch)
		l.mu.Unlock()
		close(ch)
	}
	return ch, cancel
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
