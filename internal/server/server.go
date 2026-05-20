package server

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"gaterelay/internal/config"
	"gaterelay/internal/routing"
)

type Server struct {
	cfg    *config.Config
	router *routing.Router
	client *http.Client
	logger *log.Logger
}

func New(cfg *config.Config, logger *log.Logger) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	router, err := routing.New(cfg.Routes)
	if err != nil {
		return nil, err
	}
	client, err := newUpstreamClient(cfg)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		cfg:    cfg,
		router: router,
		client: client,
		logger: logger,
	}, nil
}

func (server *Server) Handler() http.Handler {
	return http.HandlerFunc(server.ServeHTTP)
}

func (server *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}

	if server.cfg.Security.RejectEmptyHost && strings.TrimSpace(req.Host) == "" {
		http.NotFound(w, req)
		return
	}
	if server.cfg.Security.MaxRequestBodyBytes > 0 && req.Body != nil {
		req.Body = http.MaxBytesReader(w, req.Body, server.cfg.Security.MaxRequestBodyBytes)
	}

	route, matchErr := server.router.Match(req)
	if matchErr != nil {
		server.reject(w, req, matchErr)
		return
	}

	server.relay(w, req, route)
}

func (server *Server) reject(w http.ResponseWriter, req *http.Request, matchErr *routing.MatchError) {
	switch matchErr.Reason {
	case routing.RejectMethodNotAllowed:
		w.Header().Set("Allow", strings.Join(matchErr.AllowedMethods, ", "))
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	case routing.RejectUnknownHost, routing.RejectPathNotAllowed, routing.RejectEmptyToken:
		http.NotFound(w, req)
	default:
		server.logger.Printf("unexpected route rejection: %v", matchErr)
		http.Error(w, "request rejected", http.StatusForbidden)
	}
}

func newUpstreamClient(cfg *config.Config) (*http.Client, error) {
	proxyURL, err := url.Parse(cfg.OutboundHTTPProxy.URL)
	if err != nil {
		return nil, fmt.Errorf("outbound_http_proxy.url is invalid")
	}
	proxyURL.User = url.UserPassword(cfg.OutboundHTTPProxy.Username, cfg.OutboundHTTPProxy.Password)

	transport := &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		ResponseHeaderTimeout: cfg.Timeouts.UpstreamResponseHeader,
		IdleConnTimeout:       cfg.Timeouts.Idle,
		DisableCompression:    true,
	}

	return &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
