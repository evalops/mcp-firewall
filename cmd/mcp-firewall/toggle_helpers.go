package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func defaultTogglePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".mcp-firewall", "enabled")
}

func defaultRoutesPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".mcp-firewall", "routes.json")
}

func toggleStatus(path string) bool {
	if path == "" {
		return true
	}
	_, err := os.Stat(path)
	return err == nil
}

func setToggle(path string, enabled bool) error {
	if path == "" {
		return fmt.Errorf("missing toggle file")
	}
	if enabled {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("enabled\n"), 0o600)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func resolveFirewallPath() string {
	if exe, err := os.Executable(); err == nil {
		return exe
	}
	return "mcp-firewall"
}
