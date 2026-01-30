package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type hostKind string

type hostScope string

const (
	hostClaudeDesktop hostKind = "claude-desktop"
	hostCursor        hostKind = "cursor"
	hostVSCode        hostKind = "vscode"
	hostUnknown       hostKind = "unknown"
)

const (
	scopeUser      hostScope = "user"
	scopeWorkspace hostScope = "workspace"
	scopeProfile   hostScope = "profile"
)

type hostConfigFile struct {
	Host  hostKind  `json:"host"`
	Scope hostScope `json:"scope"`
	Path  string    `json:"path"`
}

type hostDiscovery struct {
	Files  []hostConfigFile `json:"files"`
	Errors []string         `json:"errors,omitempty"`
}

type hostServerInfo struct {
	Name       string   `json:"name"`
	Transport  string   `json:"transport"`
	Command    string   `json:"command,omitempty"`
	Args       []string `json:"args,omitempty"`
	URL        string   `json:"url,omitempty"`
	Wrapped    bool     `json:"wrapped"`
	Proxied    bool     `json:"proxied"`
	Message    string   `json:"message,omitempty"`
	OriginPath string   `json:"originPath"`
}

type hostFileReport struct {
	File    hostConfigFile   `json:"file"`
	Servers []hostServerInfo `json:"servers"`
	Errors  []string         `json:"errors,omitempty"`
	Changed bool             `json:"changed"`
}

type hostInstallReport struct {
	Files  []hostFileReport `json:"files"`
	Errors []string         `json:"errors,omitempty"`
}

type hostScanOptions struct {
	Roots    []string
	MaxDepth int
}

type hostInstallOptions struct {
	FirewallPath string
	PolicyPath   string
	NoNetwork    bool
	BestEffort   bool
	AllowBins    []string
	EnabledFile  string
	HTTPListen   string
	HTTPPath     string
	RoutesPath   string
	ProxyHTTP    bool
	DryRun       bool
	Backup       bool
}

func discoverHostConfigs(opts hostScanOptions) hostDiscovery {
	files := []hostConfigFile{}
	var errs []string

	configDir, err := os.UserConfigDir()
	if err != nil {
		errs = append(errs, fmt.Sprintf("failed to get user config dir: %v", err))
	} else {
		files = append(files, hostConfigFile{Host: hostClaudeDesktop, Scope: scopeUser, Path: filepath.Join(configDir, "Claude", "claude_desktop_config.json")})
		files = append(files, hostConfigFile{Host: hostCursor, Scope: scopeUser, Path: filepath.Join(configDir, "Cursor", "User", "mcp.json")})
		files = append(files, hostConfigFile{Host: hostVSCode, Scope: scopeUser, Path: filepath.Join(configDir, "Code", "User", "mcp.json")})
		profilesDir := filepath.Join(configDir, "Code", "User", "profiles")
		if entries, err := os.ReadDir(profilesDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					files = append(files, hostConfigFile{Host: hostVSCode, Scope: scopeProfile, Path: filepath.Join(profilesDir, entry.Name(), "mcp.json")})
				}
			}
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		files = append(files, hostConfigFile{Host: hostCursor, Scope: scopeUser, Path: filepath.Join(home, ".cursor", "mcp.json")})
		files = append(files, hostConfigFile{Host: hostCursor, Scope: scopeUser, Path: filepath.Join(home, ".cursor", "config.json")})
	}

	for _, root := range opts.Roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		workspaceFiles, scanErr := scanWorkspace(root, opts.MaxDepth)
		if scanErr != nil {
			errs = append(errs, scanErr.Error())
		}
		files = append(files, workspaceFiles...)
	}

	files = uniqueHostFiles(files)
	files = filterExisting(files)
	return hostDiscovery{Files: files, Errors: errs}
}

func scanWorkspace(root string, maxDepth int) ([]hostConfigFile, error) {
	if maxDepth <= 0 {
		maxDepth = 4
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("root is not a directory: %s", root)
	}
	var files []hostConfigFile
	skips := map[string]struct{}{
		".git":         {},
		"node_modules": {},
		"dist":         {},
		"build":        {},
		".cache":       {},
		".next":        {},
	}
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		depth := strings.Count(filepath.Clean(path), string(os.PathSeparator)) - rootDepth
		if d.IsDir() {
			if depth > maxDepth {
				return filepath.SkipDir
			}
			if _, ok := skips[d.Name()]; ok {
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Base(path) {
		case "mcp.json":
			parent := filepath.Base(filepath.Dir(path))
			if parent == ".vscode" {
				files = append(files, hostConfigFile{Host: hostVSCode, Scope: scopeWorkspace, Path: path})
			} else if parent == ".cursor" {
				files = append(files, hostConfigFile{Host: hostCursor, Scope: scopeWorkspace, Path: path})
			} else {
				files = append(files, hostConfigFile{Host: hostUnknown, Scope: scopeWorkspace, Path: path})
			}
		case "claude_desktop_config.json":
			files = append(files, hostConfigFile{Host: hostClaudeDesktop, Scope: scopeWorkspace, Path: path})
		}
		return nil
	})
	return files, walkErr
}

func uniqueHostFiles(files []hostConfigFile) []hostConfigFile {
	seen := map[string]hostConfigFile{}
	for _, file := range files {
		if file.Path == "" {
			continue
		}
		key := filepath.Clean(file.Path)
		if existing, ok := seen[key]; ok {
			if existing.Host == hostUnknown && file.Host != hostUnknown {
				seen[key] = file
			}
			continue
		}
		seen[key] = file
	}
	out := make([]hostConfigFile, 0, len(seen))
	for _, file := range seen {
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func filterExisting(files []hostConfigFile) []hostConfigFile {
	out := make([]hostConfigFile, 0, len(files))
	for _, file := range files {
		if file.Path == "" {
			continue
		}
		if _, err := os.Stat(file.Path); err == nil {
			out = append(out, file)
		}
	}
	return out
}

func loadConfigFile(file hostConfigFile) (map[string]interface{}, string, error) {
	data, err := os.ReadFile(file.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			root := map[string]interface{}{}
			return root, defaultServerKey(file.Host), nil
		}
		return nil, "", err
	}
	data = stripJSONComments(data)
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, "", err
	}
	key := detectServerKey(root, file.Host)
	return root, key, nil
}

func detectServerKey(root map[string]interface{}, host hostKind) string {
	if _, ok := root["mcpServers"]; ok {
		return "mcpServers"
	}
	if _, ok := root["servers"]; ok {
		return "servers"
	}
	return defaultServerKey(host)
}

func defaultServerKey(host hostKind) string {
	if host == hostVSCode {
		return "servers"
	}
	return "mcpServers"
}

func parseServers(root map[string]interface{}, key string) map[string]map[string]interface{} {
	out := map[string]map[string]interface{}{}
	val, ok := root[key]
	if !ok {
		return out
	}
	servers, ok := val.(map[string]interface{})
	if !ok {
		return out
	}
	for name, raw := range servers {
		if rawMap, ok := raw.(map[string]interface{}); ok {
			out[name] = rawMap
		}
	}
	return out
}

func stripJSONComments(data []byte) []byte {
	var out []byte
	inString := false
	escape := false
	inLine := false
	inBlock := false
	for i := 0; i < len(data); i++ {
		ch := data[i]
		next := byte(0)
		if i+1 < len(data) {
			next = data[i+1]
		}
		if inLine {
			if ch == '\n' {
				inLine = false
				out = append(out, ch)
			}
			continue
		}
		if inBlock {
			if ch == '*' && next == '/' {
				inBlock = false
				i++
			}
			continue
		}
		if inString {
			out = append(out, ch)
			if escape {
				escape = false
				continue
			}
			if ch == '\\' {
				escape = true
				continue
			}
			if ch == '"' {
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			out = append(out, ch)
			continue
		}
		if ch == '/' && next == '/' {
			inLine = true
			i++
			continue
		}
		if ch == '/' && next == '*' {
			inBlock = true
			i++
			continue
		}
		out = append(out, ch)
	}
	return out
}

func detectTransport(server map[string]interface{}) string {
	if url, ok := server["url"].(string); ok && url != "" {
		return "http"
	}
	if t, ok := server["transport"].(string); ok {
		if strings.Contains(strings.ToLower(t), "http") || strings.Contains(strings.ToLower(t), "sse") {
			return "http"
		}
	}
	if t, ok := server["type"].(string); ok {
		if strings.Contains(strings.ToLower(t), "http") || strings.Contains(strings.ToLower(t), "sse") {
			return "http"
		}
	}
	if _, ok := server["command"].(string); ok {
		return "stdio"
	}
	return "unknown"
}

func extractArgs(raw interface{}) []string {
	vals, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(vals))
	for _, val := range vals {
		if str, ok := val.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

func isWrapped(command string, args []string) bool {
	base := filepath.Base(command)
	if base == "mcp-firewall" || strings.HasSuffix(command, "mcp-firewall") {
		return true
	}
	for _, arg := range args {
		if arg == "mcp-firewall" {
			return true
		}
	}
	return false
}

func wrapStdioServer(server map[string]interface{}, opts hostInstallOptions) (bool, hostServerInfo, error) {
	info := hostServerInfo{Transport: "stdio"}
	command, _ := server["command"].(string)
	info.Command = command
	args := extractArgs(server["args"])
	info.Args = append([]string(nil), args...)
	if command == "" {
		info.Message = "missing command"
		return false, info, nil
	}
	if isWrapped(command, args) {
		info.Wrapped = true
		info.Message = "already wrapped"
		return false, info, nil
	}
	fwPath := opts.FirewallPath
	if fwPath == "" {
		fwPath = "mcp-firewall"
	}
	wrappedArgs := []string{}
	if opts.PolicyPath != "" {
		wrappedArgs = append(wrappedArgs, "--policy", opts.PolicyPath)
	}
	if opts.NoNetwork {
		wrappedArgs = append(wrappedArgs, "--no-network")
	}
	if opts.BestEffort {
		wrappedArgs = append(wrappedArgs, "--no-network-best-effort")
	}
	for _, bin := range opts.AllowBins {
		if bin != "" {
			wrappedArgs = append(wrappedArgs, "--allow-bin", bin)
		}
	}
	if opts.EnabledFile != "" {
		wrappedArgs = append(wrappedArgs, "--enabled-file", opts.EnabledFile)
	}
	wrappedArgs = append(wrappedArgs, "--", command)
	wrappedArgs = append(wrappedArgs, args...)
	server["command"] = fwPath
	server["args"] = wrappedArgs
	info.Wrapped = true
	info.Message = "wrapped with firewall"
	return true, info, nil
}

func proxyHTTPServer(name string, server map[string]interface{}, opts hostInstallOptions, routes map[string]string) (bool, hostServerInfo, error) {
	info := hostServerInfo{Transport: "http"}
	url, _ := server["url"].(string)
	info.URL = url
	if url == "" {
		info.Message = "missing url"
		return false, info, nil
	}
	if !opts.ProxyHTTP {
		info.Message = "http proxy disabled"
		return false, info, nil
	}
	if opts.HTTPListen == "" {
		info.Message = "missing http listen"
		return false, info, nil
	}
	basePath := opts.HTTPPath
	if basePath == "" {
		basePath = "/mcp"
	}
	scheme := "http"
	host := opts.HTTPListen
	if strings.HasPrefix(host, "https://") {
		scheme = "https"
		host = strings.TrimPrefix(host, "https://")
	} else if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	}
	trimBase := strings.TrimSuffix(basePath, "/")
	if strings.HasPrefix(url, fmt.Sprintf("%s://%s%s/", scheme, host, trimBase)) {
		info.Proxied = true
		info.Message = "already proxied"
		return false, info, nil
	}
	routeID := slugify(name)
	if routeID == "" {
		routeID = slugify(url)
	}
	proxyURL := fmt.Sprintf("%s://%s%s/%s", scheme, host, trimBase, routeID)
	server["url"] = proxyURL
	info.Proxied = true
	info.URL = proxyURL
	info.Message = "proxied via firewall"
	routes[routeID] = url
	return true, info, nil
}

func slugify(value string) string {
	value = strings.ToLower(value)
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		case r == '.':
			b.WriteRune('-')
		case r == '/':
			b.WriteRune('-')
		case r == ':':
			b.WriteRune('-')
		case r == '@':
			b.WriteRune('-')
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func writeConfigFile(path string, root map[string]interface{}, backup bool, dryRun bool) error {
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	if dryRun {
		return nil
	}
	if backup {
		if existing, err := os.ReadFile(path); err == nil {
			bak := path + ".bak"
			_ = os.WriteFile(bak, existing, 0o600)
		}
	}
	perm := fs.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}

func loadRoutes(path string) (map[string]string, error) {
	if path == "" {
		return map[string]string{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	var payload struct {
		Routes map[string]string `json:"routes"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if payload.Routes == nil {
		payload.Routes = map[string]string{}
	}
	return payload.Routes, nil
}

func writeRoutes(path string, routes map[string]string, dryRun bool) error {
	if path == "" {
		return nil
	}
	payload := struct {
		Routes map[string]string `json:"routes"`
	}{Routes: routes}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if dryRun {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
