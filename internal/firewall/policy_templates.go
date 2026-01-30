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

tools:
  allow:
    - "cli.*"
    - "shell.*"
  deny: []

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

prompts:
  allow: []
  deny: []
`,
		},
		{
			ID:          "local-dev",
			Name:        "Local dev (git + files)",
			Description: "Allow git and local file resources, block web/mail schemes.",
			YAML: `methods:
  deny: []

tools:
  allow:
    - "cli.*"
    - "git.*"
  deny: []

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

prompts:
  allow: []
  deny: []
`,
		},
		{
			ID:          "deny-all",
			Name:        "Deny all tools/resources",
			Description: "Allow no tools or resources; only internal prompts.",
			YAML: `methods:
  deny: []

tools:
  allow: []
  deny:
    - "*"

resources:
  allow: []
  deny:
    - "*"

prompts:
  allow: []
  deny: []
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

tools:
  allow: []
  deny: []

resources:
  allow: []
  deny: []
  allow_schemes: []
  deny_schemes: []

prompts:
  allow: []
  deny: []
`,
		Notes: []string{
			"Deny rules take precedence over allow rules.",
			"Allow lists are enforced only when non-empty.",
			"Patterns use Go path.Match (supports * and ?).",
			"Resource scheme rules apply to URI schemes (http, file, local).",
		},
	}
}
