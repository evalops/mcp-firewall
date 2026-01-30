package firewall

import "errors"

var ErrToggleUnsupported = errors.New("toggle file not configured")

type ToggleConfig struct {
	EnabledFile string
}
