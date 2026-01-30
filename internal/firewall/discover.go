package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

type DiscoverConfig struct {
	Command         []string
	ProtocolVersion string
	Framing         FramingMode
	Timeout         time.Duration
	Sandbox         SandboxConfig
}

func Discover(ctx context.Context, cfg DiscoverConfig) (Policy, error) {
	if len(cfg.Command) == 0 {
		return Policy{}, errors.New("missing server command")
	}
	if cfg.ProtocolVersion == "" {
		cfg.ProtocolVersion = "2025-06-18"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	cmd, err := newServerCommand(ctx, cfg.Command, cfg.Sandbox)
	if err != nil {
		return Policy{}, err
	}
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return Policy{}, err
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return Policy{}, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return Policy{}, err
	}
	defer func() {
		_ = serverIn.Close()
		_ = serverOut.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	codec := NewCodec(serverOut, serverIn, cfg.Framing)
	requestID := 1

	initParams := map[string]interface{}{
		"protocolVersion": cfg.ProtocolVersion,
		"clientInfo": map[string]string{
			"name":    "mcp-firewall",
			"version": "0.1",
		},
		"capabilities": map[string]interface{}{},
	}
	if err := sendRequest(codec, requestID, "initialize", initParams); err != nil {
		return Policy{}, err
	}
	if _, err := waitForResponse(codec, requestID); err != nil {
		return Policy{}, err
	}
	requestID++
	_ = sendNotification(codec, "notifications/initialized", map[string]interface{}{})

	tools, _ := listTools(codec, &requestID)
	resources, _ := listResources(codec, &requestID)
	prompts, _ := listPrompts(codec, &requestID)

	sort.Strings(tools)
	sort.Strings(resources)
	sort.Strings(prompts)

	policy := Policy{
		Tools: RuleSet{
			Allow: tools,
		},
		Resources: ResourceRules{
			Allow:        resources,
			AllowSchemes: uniqueSchemes(resources),
		},
		Prompts: RuleSet{
			Allow: prompts,
		},
	}
	return policy, nil
}

func sendRequest(codec *Codec, id int, method string, params interface{}) error {
	req := rpcMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage(fmt.Sprintf("%d", id)),
		Method:  method,
	}
	if params != nil {
		payload, err := json.Marshal(params)
		if err != nil {
			return err
		}
		req.Params = payload
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return codec.WriteMessage(data)
}

func sendNotification(codec *Codec, method string, params interface{}) error {
	req := rpcMessage{
		JSONRPC: "2.0",
		Method:  method,
	}
	if params != nil {
		payload, err := json.Marshal(params)
		if err != nil {
			return err
		}
		req.Params = payload
	}
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return codec.WriteMessage(data)
}

func waitForResponse(codec *Codec, id int) (rpcMessage, error) {
	idRaw := fmt.Sprintf("%d", id)
	for {
		msgBytes, err := codec.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return rpcMessage{}, err
			}
			return rpcMessage{}, err
		}
		var msg rpcMessage
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			continue
		}
		if normalizeID(msg.ID) == idRaw {
			if msg.Error != nil {
				return msg, fmt.Errorf("rpc error %d: %s", msg.Error.Code, msg.Error.Message)
			}
			return msg, nil
		}
	}
}

func listTools(codec *Codec, id *int) ([]string, error) {
	var names []string
	cursor := ""
	for {
		params := map[string]interface{}{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		if err := sendRequest(codec, *id, "tools/list", params); err != nil {
			return names, err
		}
		resp, err := waitForResponse(codec, *id)
		if err != nil {
			return names, err
		}
		*id = *id + 1
		var res toolListResult
		if err := json.Unmarshal(resp.Result, &res); err == nil {
			for _, tool := range res.Tools {
				if tool.Name != "" {
					names = append(names, tool.Name)
				}
			}
			if res.NextCursor == "" {
				break
			}
			cursor = res.NextCursor
		} else {
			break
		}
	}
	return uniqueStrings(names), nil
}

func listResources(codec *Codec, id *int) ([]string, error) {
	var uris []string
	cursor := ""
	for {
		params := map[string]interface{}{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		if err := sendRequest(codec, *id, "resources/list", params); err != nil {
			return uris, err
		}
		resp, err := waitForResponse(codec, *id)
		if err != nil {
			return uris, err
		}
		*id = *id + 1
		var res resourceListResult
		if err := json.Unmarshal(resp.Result, &res); err == nil {
			for _, resource := range res.Resources {
				if resource.URI != "" {
					uris = append(uris, resource.URI)
				}
			}
			if res.NextCursor == "" {
				break
			}
			cursor = res.NextCursor
		} else {
			break
		}
	}
	return uniqueStrings(uris), nil
}

func listPrompts(codec *Codec, id *int) ([]string, error) {
	var names []string
	cursor := ""
	for {
		params := map[string]interface{}{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		if err := sendRequest(codec, *id, "prompts/list", params); err != nil {
			return names, err
		}
		resp, err := waitForResponse(codec, *id)
		if err != nil {
			return names, err
		}
		*id = *id + 1
		var res promptListResult
		if err := json.Unmarshal(resp.Result, &res); err == nil {
			for _, prompt := range res.Prompts {
				if prompt.Name != "" {
					names = append(names, prompt.Name)
				}
			}
			if res.NextCursor == "" {
				break
			}
			cursor = res.NextCursor
		} else {
			break
		}
	}
	return uniqueStrings(names), nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func uniqueSchemes(uris []string) []string {
	schemes := make(map[string]struct{})
	for _, uri := range uris {
		if scheme := schemeOf(uri); scheme != "" {
			schemes[scheme] = struct{}{}
		}
	}
	out := make([]string, 0, len(schemes))
	for scheme := range schemes {
		out = append(out, scheme)
	}
	sort.Strings(out)
	return out
}
