package firewall

type PolicyTemplate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	YAML        string `json:"yaml"`
}

type PolicyHelp struct {
	Schema string   `json:"schema"`
	Notes  []string `json:"notes"`
}

func PolicyTemplates() []PolicyTemplate {
	return []PolicyTemplate{
		{
			ID:          "cli-only",
			Name:        "CLI only (local files)",
			Description: "Allow only CLI tools and local file resources.",
			YAML: `methods:
  deny: []
  strict: false
  case_insensitive: false

tools:
  allow:
    - "cli.*"
    - "shell.*"
  deny: []
  strict: false
  case_insensitive: false

resources:
  allow_schemes:
    - "file"
    - "local"
  deny_schemes:
    - "http"
    - "https"
    - "smtp"
    - "imap"
    - "s3"
  strict: false
  case_insensitive: false
  normalize: false

prompts:
  allow: []
  deny: []
  strict: false
  case_insensitive: false
`,
		},
		{
			ID:          "local-dev",
			Name:        "Local dev (git + files)",
			Description: "Allow git and local file resources, block web/mail schemes.",
			YAML: `methods:
  deny: []
  strict: false
  case_insensitive: false

tools:
  allow:
    - "cli.*"
    - "git.*"
  deny: []
  strict: false
  case_insensitive: false

resources:
  allow_schemes:
    - "file"
    - "local"
  deny_schemes:
    - "http"
    - "https"
    - "smtp"
    - "imap"
    - "s3"
  strict: false
  case_insensitive: false
  normalize: false

prompts:
  allow: []
  deny: []
  strict: false
  case_insensitive: false
`,
		},
		{
			ID:          "read-only",
			Name:        "Read-only (no tools/call)",
			Description: "Block tools/call while leaving list methods available.",
			YAML: `methods:
  deny:
    - "tools/call"
  allow: []
  strict: false
  case_insensitive: false

tools:
  allow: []
  deny:
    - "*"
  strict: false
  case_insensitive: false

resources:
  allow_schemes:
    - "file"
    - "local"
  deny_schemes:
    - "http"
    - "https"
  strict: false
  case_insensitive: false
  normalize: false

prompts:
  allow: []
  deny: []
  strict: false
  case_insensitive: false
`,
		},
		{
			ID:          "no-secrets",
			Name:        "No secrets paths",
			Description: "Block common credential/secret file paths.",
			YAML: `methods:
  deny: []
  allow: []
  strict: false
  case_insensitive: false

tools:
  allow:
    - "cli.*"
  deny: []
  strict: false
  case_insensitive: false

resources:
  allow_schemes:
    - "file"
    - "local"
  deny:
    - "**/.ssh/*"
    - "**/.aws/*"
    - "**/.gnupg/*"
    - "**/*id_rsa*"
    - "**/*id_ed25519*"
    - "**/*keychain*"
    - "**/*secrets*"
  deny_schemes:
    - "http"
    - "https"
  strict: false
  case_insensitive: false
  normalize: true

prompts:
  allow: []
  deny: []
  strict: false
  case_insensitive: false
`,
		},
		{
			ID:          "web-gateway",
			Name:        "Web via gateway",
			Description: "Only allow https resources through a proxy domain.",
			YAML: `methods:
  deny: []
  allow: []
  strict: false
  case_insensitive: false

tools:
  allow:
    - "cli.*"
  deny: []
  strict: false
  case_insensitive: false

resources:
  allow:
    - "https://proxy.example.com/*"
  allow_schemes:
    - "https"
  deny_schemes:
    - "http"
  strict: true
  case_insensitive: true
  normalize: true

prompts:
  allow: []
  deny: []
  strict: false
  case_insensitive: false
`,
		},
		{
			ID:          "strict-allowlist",
			Name:        "Strict allowlist",
			Description: "Default-deny unless explicitly allowed.",
			YAML: `methods:
  allow:
    - "tools/list"
    - "tools/call"
    - "resources/list"
    - "resources/read"
    - "prompts/list"
    - "prompts/get"
  deny: []
  strict: true
  case_insensitive: false

tools:
  allow:
    - "cli.*"
  deny: []
  strict: true
  case_insensitive: false

resources:
  allow_schemes:
    - "file"
    - "local"
  deny_schemes:
    - "http"
    - "https"
  strict: true
  case_insensitive: false
  normalize: true

prompts:
  allow: []
  deny: []
  strict: false
  case_insensitive: false
`,
		},
		{
			ID:          "deny-all",
			Name:        "Deny all tools/resources",
			Description: "Allow no tools or resources; only internal prompts.",
			YAML: `methods:
  deny: []
  allow: []
  strict: false
  case_insensitive: false

tools:
  allow: []
  deny:
    - "*"
  strict: false
  case_insensitive: false

resources:
  allow: []
  deny:
    - "*"
  strict: false
  case_insensitive: false
  normalize: false

prompts:
  allow: []
  deny: []
  strict: false
  case_insensitive: false
`,
		},
		{
			ID:          "observe-only",
			Name:        "Observe only",
			Description: "Pairs with --mode observe (logs + flag).",
			YAML: `methods:
  deny: []
  allow: []
  strict: false
  case_insensitive: false

tools:
  allow: []
  deny: []
  strict: false
  case_insensitive: false

resources:
  allow: []
  deny: []
  strict: false
  case_insensitive: false
  normalize: false

prompts:
  allow: []
  deny: []
  strict: false
  case_insensitive: false
`,
		},
	}
}

func PolicyHelpText() PolicyHelp {
	return PolicyHelp{
		Schema: `# MCP firewall policy schema
methods:
  allow: []
  deny: []
  strict: false
  case_insensitive: false

tools:
  allow: []
  deny: []
  strict: false
  case_insensitive: false

resources:
  allow: []
  deny: []
  allow_schemes: []
  deny_schemes: []
  strict: false
  case_insensitive: false
  normalize: false

prompts:
  allow: []
  deny: []
  strict: false
  case_insensitive: false

metadata:
  tools: 0
  resources: 0
  prompts: 0
  schemes: []
  generated_at: ""
  note: ""
`,
		Notes: []string{
			"Deny rules take precedence over allow rules.",
			"Allow lists are enforced only when non-empty (unless strict=true).",
			"methods.strict=true flips unknown/unspecified methods to default deny.",
			"Patterns use Go path.Match (supports * and ?), case-sensitive by default.",
			"Set case_insensitive=true to normalize pattern/value to lowercase.",
			"Resource scheme rules apply to URI schemes (http, file, local).",
			"Set normalize=true to canonicalize schemes/hosts, decode %XX, and clean paths before matching.",
		},
	}
}
