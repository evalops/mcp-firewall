package firewall

import "encoding/json"

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type resourceReadParams struct {
	URI string `json:"uri"`
}

type promptGetParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type toolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type toolListResult struct {
	Tools      []toolDef `json:"tools"`
	NextCursor string    `json:"nextCursor,omitempty"`
}

type resourceDef struct {
	URI      string `json:"uri"`
	Name     string `json:"name,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

type resourceListResult struct {
	Resources  []resourceDef `json:"resources"`
	NextCursor string        `json:"nextCursor,omitempty"`
}

type promptDef struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type promptListResult struct {
	Prompts    []promptDef `json:"prompts"`
	NextCursor string      `json:"nextCursor,omitempty"`
}
