package main

import (
	"fmt"
	"net/url"
)

func parseRouteURLs(routes map[string]string) (map[string]*url.URL, error) {
	out := map[string]*url.URL{}
	for key, raw := range routes {
		if raw == "" {
			continue
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("invalid route %s: %s", key, raw)
		}
		out[key] = parsed
	}
	return out, nil
}
