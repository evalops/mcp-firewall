package firewall

import (
	"context"
	"net/http"
	"strings"
	"time"

	"mcp-firewall/internal/firewall/ui"
	"mcp-firewall/internal/firewall/uiapi"
)

func (p *HTTPProxy) Serve(ctx context.Context, listen string) error {
	server := &http.Server{
		Addr:    listen,
		Handler: p,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	return server.ListenAndServe()
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		http.Redirect(w, r, p.uiPrefix+"/", http.StatusFound)
		return
	}
	if strings.HasPrefix(r.URL.Path, p.uiPrefix) {
		p.serveUI(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		if !p.originAllowed(r.Header.Get("Origin")) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		if p.apiHandler != nil {
			p.apiHandler.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	if !p.matchesMCPPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		p.handleGET(w, r)
	case http.MethodPost:
		p.handlePOST(w, r)
	case http.MethodDelete:
		p.handleDELETE(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (p *HTTPProxy) serveUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == p.uiPrefix || r.URL.Path == p.uiPrefix+"/" {
		r.URL.Path = "/index.html"
		p.uiHandler.ServeHTTP(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, p.uiPrefix+"/") {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, p.uiPrefix)
		p.uiHandler.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}

func (p *HTTPProxy) originAllowed(origin string) bool {
	if len(p.allowOrigins) == 0 {
		return true
	}
	if origin == "" {
		return false
	}
	for _, allowed := range p.allowOrigins {
		if allowed == "*" || strings.EqualFold(origin, allowed) {
			return true
		}
	}
	return false
}

func newAPIHandler(core *Proxy, cfg HTTPProxyConfig, maxBody int64) http.Handler {
	var history *PolicyHistory
	if cfg.PolicyHistory > 0 {
		history = NewPolicyHistory(cfg.PolicyHistory)
	}
	mode := "ui"
	upstream := ""
	if cfg.Upstream != nil {
		mode = "http-proxy"
		upstream = cfg.Upstream.String()
	}
	if cfg.Upstream == nil && len(cfg.Routes) > 0 {
		mode = "http-proxy"
		upstream = "multi"
	}
	backend := newUIBackend(core, core.logger, history, cfg.AllowPolicyWrite, cfg.PolicyPath, mode, upstream)
	return uiapi.NewHandler(uiapi.Config{
		Backend:     backend,
		APIToken:    cfg.APIToken,
		MaxBodySize: maxBody,
	})
}

func initUIHandler() http.Handler {
	return http.FileServer(http.FS(ui.FS()))
}
