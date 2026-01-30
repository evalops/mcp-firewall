package firewall

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type FramingMode int

const (
	FramingAuto FramingMode = iota
	FramingLSP
	FramingLine
)

type Codec struct {
	r    *bufio.Reader
	w    *bufio.Writer
	mode FramingMode
}

func NewCodec(r io.Reader, w io.Writer, mode FramingMode) *Codec {
	return &Codec{
		r:    bufio.NewReader(r),
		w:    bufio.NewWriter(w),
		mode: mode,
	}
}

func (c *Codec) Mode() FramingMode {
	return c.mode
}

func (c *Codec) SetMode(mode FramingMode) {
	c.mode = mode
}

func (c *Codec) ReadMessage() ([]byte, error) {
	switch c.mode {
	case FramingLSP:
		return c.readLSP()
	case FramingLine:
		return c.readLine()
	case FramingAuto:
		mode, err := c.detectMode()
		if err != nil {
			return nil, err
		}
		c.mode = mode
		return c.ReadMessage()
	default:
		return nil, errors.New("unknown framing mode")
	}
}

func (c *Codec) WriteMessage(msg []byte) error {
	mode := c.mode
	if mode == FramingAuto {
		mode = FramingLSP
	}
	var err error
	switch mode {
	case FramingLSP:
		err = c.writeLSP(msg)
	case FramingLine:
		_, err = c.w.Write(append(msg, '\n'))
	default:
		err = errors.New("unknown framing mode")
	}
	if err != nil {
		return err
	}
	return c.w.Flush()
}

func (c *Codec) detectMode() (FramingMode, error) {
	peek, err := c.r.Peek(16)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return FramingAuto, err
		}
		// If we have some bytes, keep going with what we have.
		if len(peek) == 0 {
			return FramingAuto, err
		}
	}
	lower := bytes.ToLower(peek)
	if bytes.HasPrefix(lower, []byte("content-length:")) {
		return FramingLSP, nil
	}
	if len(peek) > 0 && (peek[0] == '{' || peek[0] == '[') {
		return FramingLine, nil
	}
	return FramingLSP, nil
}

func (c *Codec) readLine() ([]byte, error) {
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) > 0 {
			return bytes.TrimSpace(line), nil
		}
		return nil, err
	}
	return bytes.TrimSpace(line), nil
}

func (c *Codec) readLSP() ([]byte, error) {
	length, err := c.readContentLength()
	if err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, errors.New("invalid content length")
	}
	payload := make([]byte, length)
	_, err = io.ReadFull(c.r, payload)
	return payload, err
}

func (c *Codec) readContentLength() (int, error) {
	contentLength := -1
	for {
		line, err := c.r.ReadString('\n')
		if err != nil {
			return 0, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				return 0, errors.New("malformed content-length header")
			}
			value := strings.TrimSpace(parts[1])
			parsed, err := strconv.Atoi(value)
			if err != nil {
				return 0, err
			}
			contentLength = parsed
		}
	}
	if contentLength < 0 {
		return 0, fmt.Errorf("missing content-length header")
	}
	return contentLength, nil
}

func (c *Codec) writeLSP(msg []byte) error {
	_, err := fmt.Fprintf(c.w, "Content-Length: %d\r\n\r\n", len(msg))
	if err != nil {
		return err
	}
	_, err = c.w.Write(msg)
	return err
}
