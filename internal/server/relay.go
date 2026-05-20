package server

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"gaterelay/internal/config"
)

func (server *Server) relay(w http.ResponseWriter, req *http.Request, route config.Route) {
	upstreamURL, err := buildUpstreamURL(route, req)
	if err != nil {
		server.logRelayError("build upstream URL failed", req, route, err)
		http.Error(w, "bad upstream configuration", http.StatusBadGateway)
		return
	}

	upstreamReq, err := http.NewRequestWithContext(req.Context(), req.Method, upstreamURL.String(), req.Body)
	if err != nil {
		server.logRelayError("build upstream request failed", req, route, err)
		http.Error(w, "bad upstream request", http.StatusBadGateway)
		return
	}
	upstreamReq.ContentLength = req.ContentLength
	copySafeHeaders(upstreamReq.Header, req.Header)

	resp, err := server.client.Do(upstreamReq)
	if err != nil {
		server.logRelayError("upstream request failed", req, route, err)
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copySafeHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		server.logRelayError("stream upstream response failed", req, route, err)
	}
}

func buildUpstreamURL(route config.Route, req *http.Request) (*url.URL, error) {
	base, err := url.Parse(route.UpstreamBase)
	if err != nil {
		return nil, err
	}

	escapedPath := req.URL.EscapedPath()
	if escapedPath == "" {
		escapedPath = "/"
	}

	joinedPath := joinEscapedPaths(base.EscapedPath(), escapedPath)
	decodedPath, err := url.PathUnescape(joinedPath)
	if err != nil {
		return nil, fmt.Errorf("invalid request path encoding: %w", err)
	}

	upstreamURL := *base
	upstreamURL.Path = decodedPath
	upstreamURL.RawPath = joinedPath
	upstreamURL.ForceQuery = false
	upstreamURL.RawQuery = ""
	upstreamURL.Fragment = ""
	if route.PassQueryString {
		upstreamURL.RawQuery = req.URL.RawQuery
	}

	return &upstreamURL, nil
}

func joinEscapedPaths(basePath, requestPath string) string {
	if basePath == "" || basePath == "/" {
		return requestPath
	}
	if requestPath == "" || requestPath == "/" {
		return basePath
	}
	if strings.HasSuffix(basePath, "/") && strings.HasPrefix(requestPath, "/") {
		return basePath + strings.TrimPrefix(requestPath, "/")
	}
	if !strings.HasSuffix(basePath, "/") && !strings.HasPrefix(requestPath, "/") {
		return basePath + "/" + requestPath
	}
	return basePath + requestPath
}

func (server *Server) logPath(path string, route config.Route) string {
	if !server.cfg.Security.HideTokenInLogs {
		return path
	}
	return redactToken(path, route.AllowedPathPrefix)
}

func (server *Server) logRelayError(message string, req *http.Request, route config.Route, err error) {
	path := ""
	if req.URL != nil {
		path = req.URL.Path
	}
	if server.cfg.Security.HideTokenInLogs {
		server.logger.Printf("%s for path %q", message, server.logPath(path, route))
		return
	}
	server.logger.Printf("%s for path %q: %v", message, path, err)
}

func redactToken(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return path
	}
	if strings.HasSuffix(prefix, "/") {
		return prefix + "<redacted>"
	}
	return strings.TrimSuffix(prefix, "/") + "/<redacted>"
}
