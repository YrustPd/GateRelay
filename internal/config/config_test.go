package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadValidConfig(t *testing.T) {
	path := writeTempConfig(t, `
listen_address: ":8080"
routes:
  - public_host: "PUBLIC.EXAMPLE.COM."
    upstream_base: "https://upstream.example.net"
    allowed_path_prefix: "/v1"
    allowed_methods:
      - get
      - POST
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
  max_request_body_bytes: 2048
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ListenAddress != ":8080" {
		t.Fatalf("ListenAddress = %q", cfg.ListenAddress)
	}
	if got := cfg.Routes[0].PublicHost; got != "public.example.com" {
		t.Fatalf("PublicHost = %q", got)
	}
	if got := cfg.Routes[0].AllowedMethods; len(got) != 2 || got[0] != "GET" || got[1] != "POST" {
		t.Fatalf("AllowedMethods = %#v", got)
	}
	if cfg.Timeouts.ReadHeader != 5*time.Second {
		t.Fatalf("ReadHeader timeout = %v", cfg.Timeouts.ReadHeader)
	}
	if cfg.Security.MaxRequestBodyBytes != 2048 {
		t.Fatalf("MaxRequestBodyBytes = %d", cfg.Security.MaxRequestBodyBytes)
	}
	if !cfg.Security.HideTokenInLogs {
		t.Fatal("HideTokenInLogs = false, want true")
	}
}

func TestParseTLSConfig(t *testing.T) {
	cfg, err := Parse([]byte(`
listen_address: ":443"
tls:
  cert_file: "/etc/gaterelay/certs/fullchain.pem"
  key_file: "/etc/gaterelay/certs/privkey.pem"
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
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.TLS.Enabled() {
		t.Fatal("TLS.Enabled() = false, want true")
	}
	if cfg.TLS.CertFile != "/etc/gaterelay/certs/fullchain.pem" {
		t.Fatalf("CertFile = %q", cfg.TLS.CertFile)
	}
	if cfg.TLS.KeyFile != "/etc/gaterelay/certs/privkey.pem" {
		t.Fatalf("KeyFile = %q", cfg.TLS.KeyFile)
	}
}

func TestParseRejectsPartialTLSConfig(t *testing.T) {
	_, err := Parse([]byte(`
listen_address: ":443"
tls:
  cert_file: "/etc/gaterelay/certs/fullchain.pem"
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
`))
	if err == nil {
		t.Fatal("Parse() error = nil, want missing tls.key_file error")
	}
}

func TestParseRejectsEmptyTLSConfig(t *testing.T) {
	_, err := Parse([]byte(`
listen_address: ":443"
tls:
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
`))
	if err == nil {
		t.Fatal("Parse() error = nil, want missing tls.cert_file error")
	}
}

func TestParseRejectsNoRoutes(t *testing.T) {
	_, err := Parse([]byte(`
listen_address: ":8080"
outbound_http_proxy:
  url: "http://proxy.example.net:8080"
  username: "YOUR_PROXY_USERNAME"
  password: "YOUR_PROXY_PASSWORD"
`))
	if err == nil {
		t.Fatal("Parse() error = nil, want missing routes error")
	}
}

func TestParseAcceptsLegacyTimeoutAliases(t *testing.T) {
	cfg, err := Parse([]byte(`
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
  read_header: "4s"
  read: "14s"
  write: "24s"
  idle: "34s"
  upstream_response_header: "44s"
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Timeouts.ReadHeader != 4*time.Second || cfg.Timeouts.Read != 14*time.Second || cfg.Timeouts.Write != 24*time.Second || cfg.Timeouts.Idle != 34*time.Second {
		t.Fatalf("timeouts = %#v", cfg.Timeouts)
	}
}

func TestParseRejectsUnknownTopLevelKey(t *testing.T) {
	_, err := Parse([]byte(`
listen_address: ":8080"
unexpected: true
routes:
  - public_host: "public.example.com"
    upstream_base: "https://upstream.example.net"
    allowed_path_prefix: "/v1"
    allowed_methods: ["GET"]
    pass_query_string: true
outbound_http_proxy:
  url: "http://proxy.example.net:8080"
  username: "YOUR_PROXY_USERNAME"
  password: "YOUR_PROXY_PASSWORD"
`))
	if err == nil {
		t.Fatal("Parse() error = nil, want unknown key error")
	}
}

func TestParseRequiresProxyURL(t *testing.T) {
	_, err := Parse([]byte(`
listen_address: ":8080"
routes:
  - public_host: "public.example.com"
    upstream_base: "https://upstream.example.net"
    allowed_path_prefix: "/v1"
    allowed_methods: ["GET"]
    pass_query_string: true
outbound_http_proxy:
  username: "YOUR_PROXY_USERNAME"
  password: "YOUR_PROXY_PASSWORD"
`))
	if err == nil {
		t.Fatal("Parse() error = nil, want missing proxy URL error")
	}
}

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
