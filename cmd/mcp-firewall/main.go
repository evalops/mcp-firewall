package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"mcp-firewall/internal/firewall"
)

func main() {
	var (
		policyPath               string
		logPath                  string
		logAllowed               bool
		logBuffer                int
		dryRun                   bool
		mode                     string
		clientFraming            string
		serverFraming            string
		listenAddr               string
		upstreamURL              string
		httpPath                 string
		uiAddr                   string
		uiPath                   string
		allowOrigins             string
		routesPath               string
		maxBodyBytes             int64
		policyWrite              bool
		apiToken                 string
		policyHistory            int
		discover                 bool
		discoverOut              string
		discoverTimeout          time.Duration
		protocolVersion          string
		inspect                  bool
		inspectThreshold         int
		inspectToolThreshold     int
		inspectResourceThreshold int
		inspectPromptThreshold   int
		inspectMaxChars          int
		inspectBlock             bool
		inspectRedact            bool
		inspectExcerpt           bool
		noNetwork                bool
		noNetworkBest            bool
		allowBins                stringList
		enabledFile              string
		enableToggle             bool
		disableToggle            bool
		statusToggle             bool
		hostScan                 bool
		hostInstall              bool
		hostUninstall            bool
		hostRestore              bool
		hostOutput               string
		hostRoots                stringList
		hostDepth                int
		hostHTTPListen           string
		hostHTTPPath             string
		hostRoutes               string
		hostDryRun               bool
		hostBackup               bool
	)

	flag.StringVar(&policyPath, "policy", "", "Path to YAML policy file")
	flag.StringVar(&logPath, "log", "", "Path to write JSONL audit logs (default stderr)")
	flag.BoolVar(&logAllowed, "log-allowed", false, "Log allowed traffic in addition to blocked")
	flag.IntVar(&logBuffer, "log-buffer", 1000, "In-memory log buffer size for the GUI (0 to disable)")
	flag.BoolVar(&dryRun, "dry-run", false, "Log what would be blocked, but allow")
	flag.StringVar(&mode, "mode", "", "Enforcement mode: observe|enforce|contain")
	flag.StringVar(&clientFraming, "client-framing", "auto", "Framing for client side: auto|lsp|line")
	flag.StringVar(&serverFraming, "server-framing", "line", "Framing for server side: auto|lsp|line")
	flag.StringVar(&listenAddr, "listen", "", "Listen address for HTTP mode (e.g. 127.0.0.1:8080)")
	flag.StringVar(&upstreamURL, "upstream", "", "Upstream MCP HTTP endpoint for HTTP mode")
	flag.StringVar(&httpPath, "path", "/mcp", "HTTP path to serve for MCP streamable HTTP")
	flag.StringVar(&uiAddr, "ui", "", "Listen address for GUI-only server (e.g. 127.0.0.1:8081)")
	flag.StringVar(&uiPath, "ui-path", "/ui", "HTTP path prefix for the GUI")
	flag.StringVar(&allowOrigins, "allow-origins", "", "Comma-separated list of allowed Origin headers for HTTP mode")
	flag.StringVar(&routesPath, "routes", "", "JSON routes file for HTTP mode (multi-upstream)")
	flag.Int64Var(&maxBodyBytes, "max-body", 20<<20, "Max HTTP request body size in bytes")
	flag.BoolVar(&policyWrite, "policy-write", false, "Allow GUI to update policy (writes file if --policy set)")
	flag.StringVar(&apiToken, "api-token", "", "Require this token for GUI/API requests (Authorization: Bearer ...)")
	flag.IntVar(&policyHistory, "policy-history", 20, "Number of policy versions to keep in GUI history")
	flag.BoolVar(&discover, "discover", false, "Discover tools/resources/prompts and emit an allowlist policy")
	flag.StringVar(&discoverOut, "discover-out", "", "Output path for discover policy (default stdout)")
	flag.DurationVar(&discoverTimeout, "discover-timeout", 10*time.Second, "Timeout for discover mode")
	flag.StringVar(&protocolVersion, "protocol-version", "2025-06-18", "MCP protocol version for discover mode")
	flag.BoolVar(&inspect, "inspect", false, "Inspect tool/resource/prompt outputs for prompt-injection patterns")
	flag.IntVar(&inspectThreshold, "inspect-threshold", 5, "Suspicion score threshold to flag outputs")
	flag.IntVar(&inspectToolThreshold, "inspect-threshold-tools", 0, "Suspicion threshold for tool outputs (overrides --inspect-threshold)")
	flag.IntVar(&inspectResourceThreshold, "inspect-threshold-resources", 0, "Suspicion threshold for resource outputs (overrides --inspect-threshold)")
	flag.IntVar(&inspectPromptThreshold, "inspect-threshold-prompts", 0, "Suspicion threshold for prompt outputs (overrides --inspect-threshold)")
	flag.IntVar(&inspectMaxChars, "inspect-max-chars", 20000, "Max chars to scan for inspection")
	flag.BoolVar(&inspectBlock, "inspect-block", false, "Block responses with suspicious output")
	flag.BoolVar(&inspectRedact, "inspect-redact", false, "Redact suspicious output text")
	flag.BoolVar(&inspectExcerpt, "inspect-excerpt", false, "Log short excerpt for suspicious matches")
	flag.BoolVar(&noNetwork, "no-network", false, "Run server command with outbound network blocked (stdio/discover only)")
	flag.BoolVar(&noNetworkBest, "no-network-best-effort", false, "Allow running without isolation if no sandbox is available")
	flag.Var(&allowBins, "allow-bin", "Allow only these executables for tool subprocesses (repeatable or comma-separated)")
	flag.StringVar(&enabledFile, "enabled-file", "", "Path to toggle file that enables enforcement (if missing, firewall is bypassed)")
	flag.BoolVar(&enableToggle, "enable", false, "Create the enabled file and exit")
	flag.BoolVar(&disableToggle, "disable", false, "Remove the enabled file and exit")
	flag.BoolVar(&statusToggle, "status", false, "Show enforcement status from the enabled file and exit")
	flag.BoolVar(&hostScan, "host-scan", false, "Discover MCP host configuration files and print a report")
	flag.BoolVar(&hostInstall, "host-install", false, "Wrap MCP host servers with the firewall")
	flag.BoolVar(&hostUninstall, "host-uninstall", false, "Remove the firewall wrapper/proxy from host configs")
	flag.BoolVar(&hostRestore, "host-restore", false, "Restore host configs from latest backups (use with --host-uninstall)")
	flag.StringVar(&hostOutput, "host-output", "", "Write host discovery/install report to this file (default stdout)")
	flag.Var(&hostRoots, "host-root", "Workspace root to scan for .vscode/mcp.json or .cursor/mcp.json (repeatable or comma-separated)")
	flag.IntVar(&hostDepth, "host-depth", 4, "Max directory depth to scan under --host-root")
	flag.StringVar(&hostHTTPListen, "host-http-listen", "127.0.0.1:17880", "HTTP listen address to use for proxied MCP servers")
	flag.StringVar(&hostHTTPPath, "host-http-path", "/mcp", "HTTP base path to use for proxied MCP servers")
	flag.StringVar(&hostRoutes, "host-routes", "", "Routes config path for HTTP proxy (default ~/.mcp-firewall/routes.json)")
	flag.BoolVar(&hostDryRun, "host-dry-run", false, "Show changes without writing host config files")
	flag.BoolVar(&hostBackup, "host-backup", true, "Write timestamped .bak files when modifying host configs")

	flag.Usage = func() {
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "Usage:")
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "  mcp-firewall [flags] -- <server command> [args]")
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "  mcp-firewall --listen :8080 --upstream http://127.0.0.1:9000/mcp [flags]")
		_, _ = fmt.Fprintln(flag.CommandLine.Output(), "  mcp-firewall --discover -- <server command> [args]")
		flag.PrintDefaults()
	}

	flag.Parse()
	cmdArgs := flag.Args()

	if enableToggle || disableToggle || statusToggle {
		path := enabledFile
		if path == "" {
			path = defaultTogglePath()
		}
		if statusToggle {
			enabled := toggleStatus(path)
			if enabled {
				fmt.Fprintln(os.Stdout, "enabled")
			} else {
				fmt.Fprintln(os.Stdout, "disabled")
			}
			return
		}
		if enableToggle {
			if err := setToggle(path, true); err != nil {
				fmt.Fprintf(os.Stderr, "failed to enable: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintln(os.Stdout, "enabled")
			return
		}
		if disableToggle {
			if err := setToggle(path, false); err != nil {
				fmt.Fprintf(os.Stderr, "failed to disable: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintln(os.Stdout, "disabled")
			return
		}
	}

	if !inspect && (inspectThreshold > 0 || inspectToolThreshold > 0 || inspectResourceThreshold > 0 || inspectPromptThreshold > 0) {
		inspect = true
	}

	mode = strings.ToLower(strings.TrimSpace(mode))
	enforcementMode := ""
	if mode != "" {
		switch mode {
		case "observe":
			dryRun = true
			enforcementMode = "observe"
		case "enforce":
			dryRun = false
			enforcementMode = "enforce"
		case "contain":
			dryRun = false
			enforcementMode = "contain"
			if !noNetwork {
				noNetwork = true
			}
		default:
			fmt.Fprintf(os.Stderr, "invalid --mode %q (expected observe|enforce|contain)\n", mode)
			os.Exit(2)
		}
	} else {
		if dryRun {
			enforcementMode = "observe"
		} else {
			enforcementMode = "enforce"
		}
		if enforcementMode == "enforce" && (noNetwork || len(allowBins) > 0) {
			enforcementMode = "contain"
		}
	}
	if enforcementMode == "contain" && len(allowBins) == 0 {
		fmt.Fprintln(os.Stderr, "warning: contain mode without --allow-bin still permits arbitrary binaries")
	}

	if hostInstall && hostUninstall {
		fmt.Fprintln(os.Stderr, "--host-install and --host-uninstall are mutually exclusive")
		os.Exit(2)
	}
	if hostRestore && !hostUninstall {
		fmt.Fprintln(os.Stderr, "--host-restore requires --host-uninstall")
		os.Exit(2)
	}

	if hostScan || hostInstall || hostUninstall {
		if hostRoutes == "" {
			hostRoutes = defaultRoutesPath()
		}
		if len(hostRoots) == 0 {
			hostRoots = stringList{"."}
		}
		scan := discoverHostConfigs(hostScanOptions{Roots: hostRoots, MaxDepth: hostDepth})
		report := hostInstallReport{}
		var routes map[string]string
		routesChanged := false
		fwPath := ""
		if len(scan.Errors) > 0 {
			report.Errors = append(report.Errors, scan.Errors...)
		}
		if hostInstall {
			fwPath = resolveFirewallPath()
			if enabledFile == "" {
				enabledFile = defaultTogglePath()
			}
			loaded, err := loadRoutes(hostRoutes)
			if err != nil {
				report.Errors = append(report.Errors, err.Error())
			} else {
				routes = loaded
			}
			if routes == nil {
				routes = map[string]string{}
			}
		}
		if hostUninstall {
			if enabledFile == "" {
				enabledFile = defaultTogglePath()
			}
			loaded, err := loadRoutes(hostRoutes)
			if err != nil {
				report.Errors = append(report.Errors, err.Error())
			} else {
				routes = loaded
			}
			if routes == nil {
				routes = map[string]string{}
			}
		}
		for _, file := range scan.Files {
			root, key, _, err := loadConfigFile(file)
			fileReport := hostFileReport{File: file}
			if err != nil {
				fileReport.Errors = append(fileReport.Errors, err.Error())
				report.Files = append(report.Files, fileReport)
				continue
			}
			servers := parseServers(root, key)
			if !hostInstall && !hostUninstall {
				for name, server := range servers {
					transport := detectTransport(server)
					info := hostServerInfo{Name: name, Transport: transport, OriginPath: file.Path}
					switch transport {
					case "stdio":
						cmd, _ := server["command"].(string)
						info.Command = cmd
						info.Args = extractArgs(server["args"])
						info.Wrapped = isWrapped(info.Command, info.Args)
					case "http":
						if url, _ := server["url"].(string); url != "" {
							info.URL = url
						}
					}
					fileReport.Servers = append(fileReport.Servers, info)
				}
				report.Files = append(report.Files, fileReport)
				continue
			}

			originalData, _ := marshalConfig(root)

			if hostUninstall {
				if hostRestore {
					if backupPath, err := latestBackup(file.Path); err == nil {
						if backupBytes, err := os.ReadFile(backupPath); err == nil && hostDryRun {
							fileReport.Diff = diffText(string(originalData), string(backupBytes))
						}
						if err := restoreBackup(file.Path, backupPath, hostDryRun); err != nil {
							fileReport.Errors = append(fileReport.Errors, err.Error())
						} else {
							fileReport.Restored = true
							fileReport.Changed = true
							fileReport.BackupPath = backupPath
						}
					} else {
						fileReport.Errors = append(fileReport.Errors, err.Error())
					}
					report.Files = append(report.Files, fileReport)
					continue
				}
				changed := false
				for name, server := range servers {
					transport := detectTransport(server)
					if transport == "stdio" {
						updated, info, err := unwrapStdioServer(server)
						info.Name = name
						info.OriginPath = file.Path
						if err != nil {
							fileReport.Errors = append(fileReport.Errors, err.Error())
						} else {
							fileReport.Servers = append(fileReport.Servers, info)
						}
						changed = changed || updated
						continue
					}
					if transport == "http" {
						updated, info, err := unproxyHTTPServer(name, server, hostInstallOptions{
							HTTPListen: hostHTTPListen,
							HTTPPath:   hostHTTPPath,
							RoutesPath: hostRoutes,
						}, routes)
						info.Name = name
						info.OriginPath = file.Path
						if err != nil {
							fileReport.Errors = append(fileReport.Errors, err.Error())
						} else {
							fileReport.Servers = append(fileReport.Servers, info)
						}
						changed = changed || updated
						routesChanged = routesChanged || updated
					}
				}
				if changed {
					root[key] = servers
					if nextData, err := marshalConfig(root); err == nil {
						if hostDryRun {
							fileReport.Diff = diffText(string(originalData), string(nextData))
						}
						if backupPath, err := writeConfigFile(file.Path, nextData, hostBackup, hostDryRun); err != nil {
							fileReport.Errors = append(fileReport.Errors, err.Error())
						} else {
							fileReport.BackupPath = backupPath
						}
					} else {
						fileReport.Errors = append(fileReport.Errors, err.Error())
					}
					fileReport.Changed = true
				}
				report.Files = append(report.Files, fileReport)
				continue
			}

			changed := false
			for name, server := range servers {
				transport := detectTransport(server)
				if transport == "stdio" {
					updated, info, err := wrapStdioServer(server, hostInstallOptions{
						FirewallPath: fwPath,
						PolicyPath:   policyPath,
						Mode:         enforcementMode,
						NoNetwork:    noNetwork,
						BestEffort:   noNetworkBest,
						AllowBins:    allowBins,
						EnabledFile:  enabledFile,
						DryRun:       hostDryRun,
						Backup:       hostBackup,
					})
					info.Name = name
					info.OriginPath = file.Path
					if err != nil {
						fileReport.Errors = append(fileReport.Errors, err.Error())
					} else {
						fileReport.Servers = append(fileReport.Servers, info)
					}
					changed = changed || updated
					continue
				}
				if transport == "http" {
					updated, info, err := proxyHTTPServer(name, server, hostInstallOptions{
						HTTPListen: hostHTTPListen,
						HTTPPath:   hostHTTPPath,
						RoutesPath: hostRoutes,
						ProxyHTTP:  true,
						DryRun:     hostDryRun,
						Backup:     hostBackup,
					}, routes)
					info.Name = name
					info.OriginPath = file.Path
					if err != nil {
						fileReport.Errors = append(fileReport.Errors, err.Error())
					} else {
						fileReport.Servers = append(fileReport.Servers, info)
					}
					changed = changed || updated
					routesChanged = routesChanged || updated
				}
			}
			if changed {
				root[key] = servers
				if nextData, err := marshalConfig(root); err == nil {
					if hostDryRun {
						fileReport.Diff = diffText(string(originalData), string(nextData))
					}
					if backupPath, err := writeConfigFile(file.Path, nextData, hostBackup, hostDryRun); err != nil {
						fileReport.Errors = append(fileReport.Errors, err.Error())
					} else {
						fileReport.BackupPath = backupPath
					}
				} else {
					fileReport.Errors = append(fileReport.Errors, err.Error())
				}
				fileReport.Changed = true
			}
			report.Files = append(report.Files, fileReport)
		}

		if hostInstall && routesChanged {
			if _, err := writeRoutes(hostRoutes, routes, hostBackup, hostDryRun); err != nil {
				report.Errors = append(report.Errors, err.Error())
			}
		}
		if hostUninstall {
			if hostRestore {
				if backupPath, err := latestBackup(hostRoutes); err == nil {
					if err := restoreBackup(hostRoutes, backupPath, hostDryRun); err != nil {
						report.Errors = append(report.Errors, err.Error())
					}
				}
			} else if routesChanged {
				if _, err := writeRoutes(hostRoutes, routes, hostBackup, hostDryRun); err != nil {
					report.Errors = append(report.Errors, err.Error())
				}
			}
		}

		if hostInstall && enabledFile != "" && !hostDryRun {
			if err := setToggle(enabledFile, true); err != nil {
				report.Errors = append(report.Errors, err.Error())
			}
		}
		if hostUninstall && enabledFile != "" && !hostDryRun {
			if err := setToggle(enabledFile, false); err != nil {
				report.Errors = append(report.Errors, err.Error())
			}
		}

		output, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode report: %v\n", err)
			os.Exit(1)
		}
		if hostOutput == "" {
			_, _ = os.Stdout.Write(output)
			_, _ = os.Stdout.Write([]byte("\n"))
		} else {
			if err := os.WriteFile(hostOutput, output, 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write report: %v\n", err)
				os.Exit(1)
			}
		}
		return
	}

	policy := firewall.Policy{}
	if policyPath != "" {
		data, err := os.ReadFile(policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read policy: %v\n", err)
			os.Exit(1)
		}
		if err := yaml.Unmarshal(data, &policy); err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse policy: %v\n", err)
			os.Exit(1)
		}
	}

	logWriter := io.Writer(os.Stderr)
	if logPath != "" {
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open log file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		logWriter = file
	}

	logger := firewall.NewLoggerWithOptions(logWriter, firewall.LoggerOptions{
		LogAllowed: logAllowed,
		MaxBuffer:  logBuffer,
	})
	inspectCfg := firewall.InspectorConfig{
		Enabled:           inspect,
		Threshold:         inspectThreshold,
		ToolThreshold:     inspectToolThreshold,
		ResourceThreshold: inspectResourceThreshold,
		PromptThreshold:   inspectPromptThreshold,
		MaxChars:          inspectMaxChars,
		Block:             inspectBlock,
		Redact:            inspectRedact,
		LogExcerpt:        inspectExcerpt,
	}
	opts := firewall.ProxyOptions{
		Logger:  logger,
		DryRun:  dryRun,
		Mode:    enforcementMode,
		Inspect: inspectCfg,
		Sandbox: firewall.SandboxConfig{
			NoNetwork:       noNetwork,
			BestEffort:      noNetworkBest,
			AllowedBinaries: allowBins,
		},
		Toggle: firewall.ToggleConfig{
			EnabledFile: enabledFile,
		},
	}

	if discover {
		if len(cmdArgs) == 0 {
			flag.Usage()
			os.Exit(2)
		}
		cfg := firewall.DiscoverConfig{
			Command:         cmdArgs,
			ProtocolVersion: protocolVersion,
			Framing:         parseFraming(serverFraming),
			Timeout:         discoverTimeout,
			Sandbox: firewall.SandboxConfig{
				NoNetwork:       noNetwork,
				BestEffort:      noNetworkBest,
				AllowedBinaries: allowBins,
			},
		}
		outPolicy, err := firewall.Discover(context.Background(), cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "discover error: %v\n", err)
			os.Exit(1)
		}
		output, err := yaml.Marshal(outPolicy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to encode policy: %v\n", err)
			os.Exit(1)
		}
		if discoverOut == "" {
			_, _ = os.Stdout.Write(output)
		} else {
			if err := os.WriteFile(discoverOut, output, 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write discover policy: %v\n", err)
				os.Exit(1)
			}
		}
		return
	}

	core := firewall.NewProxy(policy, opts)

	if listenAddr != "" {
		var routes map[string]*url.URL
		if routesPath != "" {
			routeMap, err := loadRoutes(routesPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to load routes: %v\n", err)
				os.Exit(1)
			}
			parsed, err := parseRouteURLs(routeMap)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid routes: %v\n", err)
				os.Exit(1)
			}
			routes = parsed
		}
		if noNetwork || len(allowBins) > 0 {
			fmt.Fprintln(os.Stderr, "warning: --no-network/--allow-bin apply only to stdio/discover; HTTP upstream is not sandboxed")
		}
		var parsed *url.URL
		if upstreamURL != "" {
			var err error
			parsed, err = parseURL(upstreamURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid upstream url: %v\n", err)
				os.Exit(2)
			}
		}
		httpProxy := firewall.NewHTTPProxy(core, firewall.HTTPProxyConfig{
			Upstream:         parsed,
			Routes:           routes,
			AllowOrigins:     parseList(allowOrigins),
			Path:             httpPath,
			UIPrefix:         uiPath,
			PolicyPath:       policyPath,
			AllowPolicyWrite: policyWrite,
			APIToken:         apiToken,
			PolicyHistory:    policyHistory,
			MaxBodyBytes:     maxBodyBytes,
		})
		if err := httpProxy.Serve(context.Background(), listenAddr); err != nil {
			fmt.Fprintf(os.Stderr, "http firewall error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if uiAddr != "" && len(cmdArgs) == 0 {
		if noNetwork || len(allowBins) > 0 {
			fmt.Fprintln(os.Stderr, "warning: --no-network/--allow-bin apply only to stdio/discover; UI-only mode does not spawn a server command")
		}
		uiProxy := firewall.NewHTTPProxy(core, firewall.HTTPProxyConfig{
			AllowOrigins:     parseList(allowOrigins),
			Path:             httpPath,
			UIPrefix:         uiPath,
			PolicyPath:       policyPath,
			AllowPolicyWrite: policyWrite,
			APIToken:         apiToken,
			PolicyHistory:    policyHistory,
			MaxBodyBytes:     maxBodyBytes,
		})
		if err := uiProxy.Serve(context.Background(), uiAddr); err != nil {
			fmt.Fprintf(os.Stderr, "ui server error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(cmdArgs) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	if uiAddr != "" {
		uiProxy := firewall.NewHTTPProxy(core, firewall.HTTPProxyConfig{
			AllowOrigins:     parseList(allowOrigins),
			Path:             httpPath,
			UIPrefix:         uiPath,
			PolicyPath:       policyPath,
			AllowPolicyWrite: policyWrite,
			APIToken:         apiToken,
			PolicyHistory:    policyHistory,
			MaxBodyBytes:     maxBodyBytes,
		})
		go func() {
			if err := uiProxy.Serve(context.Background(), uiAddr); err != nil {
				fmt.Fprintf(os.Stderr, "ui server error: %v\n", err)
			}
		}()
	}

	proxy := core
	cfg := firewall.RunConfig{
		Command:       cmdArgs,
		ClientFraming: parseFraming(clientFraming),
		ServerFraming: parseFraming(serverFraming),
		Sandbox: firewall.SandboxConfig{
			NoNetwork:       noNetwork,
			BestEffort:      noNetworkBest,
			AllowedBinaries: allowBins,
		},
	}

	if err := proxy.Run(context.Background(), os.Stdin, os.Stdout, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "firewall error: %v\n", err)
		os.Exit(1)
	}
}

func parseFraming(value string) firewall.FramingMode {
	switch strings.ToLower(value) {
	case "auto":
		return firewall.FramingAuto
	case "lsp":
		return firewall.FramingLSP
	case "line":
		return firewall.FramingLine
	default:
		return firewall.FramingAuto
	}
}

func parseList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("missing scheme or host")
	}
	return parsed, nil
}

type stringList []string

func (s *stringList) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			*s = append(*s, item)
		}
	}
	return nil
}
