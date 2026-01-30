package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
	File       hostConfigFile   `json:"file"`
	Servers    []hostServerInfo `json:"servers"`
	Errors     []string         `json:"errors,omitempty"`
	Changed    bool             `json:"changed"`
	Restored   bool             `json:"restored,omitempty"`
	BackupPath string           `json:"backupPath,omitempty"`
	Diff       string           `json:"diff,omitempty"`
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
	Mode         string
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
		vscodeDirs := []string{"Code", "Code - Insiders", "VSCodium"}
		for _, dir := range vscodeDirs {
			files = append(files, hostConfigFile{Host: hostVSCode, Scope: scopeUser, Path: filepath.Join(configDir, dir, "User", "mcp.json")})
			profilesDir := filepath.Join(configDir, dir, "User", "profiles")
			if entries, err := os.ReadDir(profilesDir); err == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						files = append(files, hostConfigFile{Host: hostVSCode, Scope: scopeProfile, Path: filepath.Join(profilesDir, entry.Name(), "mcp.json")})
					}
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

func loadConfigFile(file hostConfigFile) (map[string]interface{}, string, []byte, error) {
	data, err := os.ReadFile(file.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			root := map[string]interface{}{}
			return root, defaultServerKey(file.Host), nil, nil
		}
		return nil, "", nil, err
	}
	data = stripJSONComments(data)
	var root map[string]interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, "", nil, err
	}
	key := detectServerKey(root, file.Host)
	return root, key, data, nil
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
	if opts.Mode != "" {
		wrappedArgs = append(wrappedArgs, "--mode", opts.Mode)
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

func marshalConfig(root map[string]interface{}) ([]byte, error) {
	return json.MarshalIndent(root, "", "  ")
}

func writeConfigFile(path string, data []byte, backup bool, dryRun bool) (string, error) {
	if dryRun {
		return "", nil
	}
	var backupPath string
	if backup {
		if _, err := os.Stat(path); err == nil {
			var err error
			backupPath, err = backupFile(path)
			if err != nil {
				return "", err
			}
		}
	}
	perm := fs.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	return backupPath, os.WriteFile(path, data, perm)
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

func writeRoutes(path string, routes map[string]string, backup bool, dryRun bool) (string, error) {
	if path == "" {
		return "", nil
	}
	payload := struct {
		Routes map[string]string `json:"routes"`
	}{Routes: routes}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", err
	}
	if dryRun {
		return "", nil
	}
	var backupPath string
	if backup {
		if _, err := os.Stat(path); err == nil {
			var err error
			backupPath, err = backupFile(path)
			if err != nil {
				return "", err
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	return backupPath, os.WriteFile(path, data, 0o600)
}

func backupFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	ts := time.Now().UTC().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.bak-%s", path, ts)
	if err := os.WriteFile(backupPath, data, 0o600); err != nil {
		return "", err
	}
	return backupPath, nil
}

func latestBackup(path string) (string, error) {
	matches, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		return "", err
	}
	if len(matches) == 0 {
		return "", os.ErrNotExist
	}
	type candidate struct {
		path string
		mod  time.Time
	}
	best := candidate{}
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}
		if best.path == "" || info.ModTime().After(best.mod) {
			best = candidate{path: match, mod: info.ModTime()}
		}
	}
	if best.path == "" {
		return "", os.ErrNotExist
	}
	return best.path, nil
}

func restoreBackup(path string, backupPath string, dryRun bool) error {
	if dryRun {
		return nil
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	perm := fs.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	} else if info, err := os.Stat(backupPath); err == nil {
		perm = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}

func diffText(current string, next string) string {
	if current == next {
		return ""
	}
	currentLines := strings.Split(current, "\n")
	nextLines := strings.Split(next, "\n")
	var sb strings.Builder
	sb.WriteString("--- current\n+++ proposed\n")
	max := len(currentLines)
	if len(nextLines) > max {
		max = len(nextLines)
	}
	for i := 0; i < max; i++ {
		var left, right string
		if i < len(currentLines) {
			left = currentLines[i]
		}
		if i < len(nextLines) {
			right = nextLines[i]
		}
		if left == right {
			continue
		}
		if left != "" {
			sb.WriteString("-")
			sb.WriteString(left)
			sb.WriteString("\n")
		}
		if right != "" {
			sb.WriteString("+")
			sb.WriteString(right)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func isFirewallCommand(command string) bool {
	base := filepath.Base(command)
	return base == "mcp-firewall" || strings.HasSuffix(command, "mcp-firewall")
}

func unwrapStdioServer(server map[string]interface{}) (bool, hostServerInfo, error) {
	info := hostServerInfo{Transport: "stdio"}
	command, _ := server["command"].(string)
	info.Command = command
	args := extractArgs(server["args"])
	info.Args = append([]string(nil), args...)
	if command == "" {
		info.Message = "missing command"
		return false, info, nil
	}
	if !isFirewallCommand(command) {
		info.Message = "not wrapped"
		return false, info, nil
	}
	idx := -1
	for i, arg := range args {
		if arg == "--" {
			idx = i
			break
		}
	}
	if idx == -1 || idx+1 >= len(args) {
		info.Message = "missing original command"
		return false, info, nil
	}
	originalCmd := args[idx+1]
	originalArgs := args[idx+2:]
	server["command"] = originalCmd
	server["args"] = originalArgs
	info.Command = originalCmd
	info.Args = append([]string(nil), originalArgs...)
	info.Message = "unwrapped firewall"
	return true, info, nil
}

func unproxyHTTPServer(name string, server map[string]interface{}, opts hostInstallOptions, routes map[string]string) (bool, hostServerInfo, error) {
	info := hostServerInfo{Transport: "http"}
	urlStr, _ := server["url"].(string)
	info.URL = urlStr
	if urlStr == "" {
		info.Message = "missing url"
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
	parsed, err := url.Parse(urlStr)
	if err != nil {
		info.Message = "invalid url"
		return false, info, nil
	}
	trimBase := strings.TrimSuffix(basePath, "/")
	if parsed.Scheme != scheme || parsed.Host != host || !strings.HasPrefix(parsed.Path, trimBase+"/") {
		info.Message = "not proxied"
		return false, info, nil
	}
	rest := strings.TrimPrefix(parsed.Path, trimBase+"/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		info.Message = "missing route id"
		return false, info, nil
	}
	routeID := parts[0]
	if routes != nil {
		if original, ok := routes[routeID]; ok && original != "" {
			server["url"] = original
			info.URL = original
			delete(routes, routeID)
			info.Message = "restored from routes"
			return true, info, nil
		}
	}
	info.Message = "route mapping not found"
	return false, info, nil
}
