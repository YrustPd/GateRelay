package main

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gaterelay/internal/config"
)

func TestRunCheckConfig(t *testing.T) {
	configPath := writeCommandTestConfig(t)

	var logs bytes.Buffer
	err := run([]string{"-config", configPath, "-check-config"}, log.New(&logs, "", 0))
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !strings.Contains(logs.String(), "configuration OK") {
		t.Fatalf("logs = %q, want configuration OK", logs.String())
	}
}

func TestRunCheckConfigReturnsConfigError(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(`listen_address: ":8080"`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"-config", configPath, "-check-config"}, log.New(&bytes.Buffer{}, "", 0))
	if err == nil {
		t.Fatal("run() error = nil, want config validation error")
	}
}

func TestNewHTTPServerMapsConfiguredTimeouts(t *testing.T) {
	cfg := &config.Config{
		ListenAddress: ":8443",
		Timeouts: config.Timeouts{
			ReadHeader: 2 * time.Second,
			Read:       3 * time.Second,
			Write:      4 * time.Second,
			Idle:       5 * time.Second,
		},
	}

	httpServer := newHTTPServer(cfg, http.NotFoundHandler())
	if httpServer.Addr != ":8443" {
		t.Fatalf("Addr = %q", httpServer.Addr)
	}
	if httpServer.ReadHeaderTimeout != 2*time.Second {
		t.Fatalf("ReadHeaderTimeout = %v", httpServer.ReadHeaderTimeout)
	}
	if httpServer.ReadTimeout != 3*time.Second {
		t.Fatalf("ReadTimeout = %v", httpServer.ReadTimeout)
	}
	if httpServer.WriteTimeout != 4*time.Second {
		t.Fatalf("WriteTimeout = %v", httpServer.WriteTimeout)
	}
	if httpServer.IdleTimeout != 5*time.Second {
		t.Fatalf("IdleTimeout = %v", httpServer.IdleTimeout)
	}
}

func writeCommandTestConfig(t *testing.T) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	contents := `
listen_address: ":8080"
routes:
  - public_host: "public.example.com"
    upstream_base: "https://upstream.example.net"
    allowed_path_prefix: "/sub/"
    allowed_methods: ["GET"]
    pass_query_string: true
outbound_http_proxy:
  url: "http://proxy.example.net:8080"
  username: "YOUR_PROXY_USERNAME"
  password: "YOUR_PROXY_PASSWORD"
timeouts:
  read_header_timeout: "5s"
  read_timeout: "15s"
  write_timeout: "30s"
  idle_timeout: "60s"
  upstream_response_header: "30s"
security:
  reject_empty_host: true
  hide_token_in_logs: true
  max_request_body_bytes: 1048576
`
	if err := os.WriteFile(configPath, []byte(contents), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath
}
