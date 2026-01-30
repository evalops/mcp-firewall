package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

var ErrNoNetworkUnsupported = errors.New("no-network sandbox unavailable")
var ErrExecAllowlistUnsupported = errors.New("executable allowlist sandbox unavailable")

type SandboxConfig struct {
	NoNetwork       bool
	BestEffort      bool
	AllowedBinaries []string
}

func newServerCommand(ctx context.Context, command []string, sandbox SandboxConfig) (*exec.Cmd, error) {
	if len(command) == 0 {
		return nil, errors.New("missing server command")
	}
	if !sandbox.NoNetwork && len(sandbox.AllowedBinaries) == 0 {
		return exec.CommandContext(ctx, command[0], command[1:]...), nil
	}
	cmd, err := commandSandbox(ctx, command, sandbox)
	if err != nil {
		if sandbox.BestEffort {
			fallback := exec.CommandContext(ctx, command[0], command[1:]...)
			env := append(os.Environ(), "MCP_FIREWALL_NO_NETWORK=1")
			if len(sandbox.AllowedBinaries) > 0 {
				env = append(env, "MCP_FIREWALL_ALLOW_BIN="+strings.Join(sandbox.AllowedBinaries, ","))
			}
			fallback.Env = env
			fmt.Fprintln(os.Stderr, "warning: sandbox unavailable; running without isolation")
			return fallback, nil
		}
		return nil, err
	}
	return cmd, nil
}

func commandSandbox(ctx context.Context, command []string, sandbox SandboxConfig) (*exec.Cmd, error) {
	allowPaths, allowNames, err := resolveAllowlist(command, sandbox.AllowedBinaries)
	if err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "darwin":
		path, err := exec.LookPath("sandbox-exec")
		if err != nil {
			if len(allowPaths) > 0 {
				return nil, ErrExecAllowlistUnsupported
			}
			return nil, ErrNoNetworkUnsupported
		}
		profile := buildSandboxProfile(sandbox.NoNetwork, allowPaths)
		args := append([]string{"-p", profile, "--"}, command...)
		return exec.CommandContext(ctx, path, args...), nil
	case "linux":
		if path, err := exec.LookPath("firejail"); err == nil {
			args := []string{"--quiet"}
			if sandbox.NoNetwork {
				args = append(args, "--net=none")
			}
			if len(allowNames) > 0 {
				args = append(args, "--private-bin="+strings.Join(allowNames, ","))
			}
			args = append(args, "--")
			args = append(args, command...)
			return exec.CommandContext(ctx, path, args...), nil
		}
		if len(allowNames) > 0 {
			return nil, ErrExecAllowlistUnsupported
		}
		if sandbox.NoNetwork {
			if path, err := exec.LookPath("unshare"); err == nil {
				args := append([]string{"-n", "--"}, command...)
				return exec.CommandContext(ctx, path, args...), nil
			}
		}
		return nil, ErrNoNetworkUnsupported
	default:
		return nil, fmt.Errorf("%w on %s", ErrNoNetworkUnsupported, runtime.GOOS)
	}
}

func resolveAllowlist(command []string, allowlist []string) ([]string, []string, error) {
	if len(allowlist) == 0 {
		return nil, nil, nil
	}
	pathSet := make(map[string]struct{})
	nameSet := make(map[string]struct{})
	addPath := func(value string) {
		if value == "" {
			return
		}
		clean := filepath.Clean(value)
		if !filepath.IsAbs(clean) {
			if abs, err := filepath.Abs(clean); err == nil {
				clean = abs
			}
		}
		pathSet[clean] = struct{}{}
		nameSet[filepath.Base(clean)] = struct{}{}
	}
	mainPath, err := exec.LookPath(command[0])
	if err != nil {
		return nil, nil, fmt.Errorf("server command not found: %w", err)
	}
	addPath(mainPath)
	for _, entry := range allowlist {
		if entry == "" {
			continue
		}
		resolved, err := exec.LookPath(entry)
		if err != nil {
			return nil, nil, fmt.Errorf("allow-bin not found: %s", entry)
		}
		addPath(resolved)
	}
	paths := make([]string, 0, len(pathSet))
	for path := range pathSet {
		paths = append(paths, path)
	}
	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	return paths, names, nil
}

func buildSandboxProfile(noNetwork bool, allowPaths []string) string {
	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	if noNetwork {
		sb.WriteString("(deny network*)\n")
	}
	if len(allowPaths) > 0 {
		sb.WriteString("(deny process-exec)\n")
		for _, entry := range allowPaths {
			sb.WriteString("(allow process-exec (literal ")
			sb.WriteString(strconv.Quote(entry))
			sb.WriteString("))\n")
		}
	}
	sb.WriteString("(allow default)\n")
	return sb.String()
}
