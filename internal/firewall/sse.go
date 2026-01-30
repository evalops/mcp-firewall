package firewall

import (
	"bufio"
	"bytes"
	"io"
	"strings"
)

type sseEvent struct {
	Event string
	ID    string
	Retry string
	Data  string
}

func readSSEEvent(r *bufio.Reader) (sseEvent, error) {
	var event sseEvent
	var dataLines []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF && line == "" {
				return event, io.EOF
			}
			if err != io.EOF {
				return event, err
			}
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		field := parts[0]
		value := ""
		if len(parts) == 2 {
			value = strings.TrimLeft(parts[1], " ")
		}
		switch field {
		case "event":
			event.Event = value
		case "id":
			event.ID = value
		case "retry":
			event.Retry = value
		case "data":
			dataLines = append(dataLines, value)
		default:
			// ignore unknown fields
		}
		if err == io.EOF {
			break
		}
	}
	event.Data = strings.Join(dataLines, "\n")
	return event, nil
}

func writeSSEEvent(w io.Writer, event sseEvent) error {
	var buf bytes.Buffer
	if event.Event != "" {
		buf.WriteString("event: ")
		buf.WriteString(event.Event)
		buf.WriteString("\n")
	}
	if event.ID != "" {
		buf.WriteString("id: ")
		buf.WriteString(event.ID)
		buf.WriteString("\n")
	}
	if event.Retry != "" {
		buf.WriteString("retry: ")
		buf.WriteString(event.Retry)
		buf.WriteString("\n")
	}
	if event.Data != "" {
		for _, line := range strings.Split(event.Data, "\n") {
			buf.WriteString("data: ")
			buf.WriteString(line)
			buf.WriteString("\n")
		}
	}
	buf.WriteString("\n")
	_, err := w.Write(buf.Bytes())
	return err
}
