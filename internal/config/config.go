package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultReadHeaderTimeout            = 5 * time.Second
	defaultReadTimeout                  = 15 * time.Second
	defaultWriteTimeout                 = 30 * time.Second
	defaultIdleTimeout                  = 60 * time.Second
	defaultUpstreamResponseHeader       = 30 * time.Second
	defaultMaxRequestBodyBytes    int64 = 1 << 20
)

type Config struct {
	ListenAddress     string
	TLS               TLSConfig
	Routes            []Route
	OutboundHTTPProxy OutboundHTTPProxy
	Timeouts          Timeouts
	Security          Security
}

type Route struct {
	PublicHost        string
	UpstreamBase      string
	AllowedPathPrefix string
	AllowedMethods    []string
	PassQueryString   bool
}

type OutboundHTTPProxy struct {
	URL      string
	Username string
	Password string
}

type TLSConfig struct {
	CertFile string
	KeyFile  string

	configured bool
}

func (tls TLSConfig) Enabled() bool {
	return tls.configured || strings.TrimSpace(tls.CertFile) != "" || strings.TrimSpace(tls.KeyFile) != ""
}

type Timeouts struct {
	ReadHeader             time.Duration
	Read                   time.Duration
	Write                  time.Duration
	Idle                   time.Duration
	UpstreamResponseHeader time.Duration
}

type Security struct {
	RejectEmptyHost     bool
	HideTokenInLogs     bool
	MaxRequestBodyBytes int64
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	cfg, err := parseYAMLConfig(data)
	if err != nil {
		return nil, err
	}
	applyDefaults(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Timeouts.ReadHeader == 0 {
		cfg.Timeouts.ReadHeader = defaultReadHeaderTimeout
	}
	if cfg.Timeouts.Read == 0 {
		cfg.Timeouts.Read = defaultReadTimeout
	}
	if cfg.Timeouts.Write == 0 {
		cfg.Timeouts.Write = defaultWriteTimeout
	}
	if cfg.Timeouts.Idle == 0 {
		cfg.Timeouts.Idle = defaultIdleTimeout
	}
	if cfg.Timeouts.UpstreamResponseHeader == 0 {
		cfg.Timeouts.UpstreamResponseHeader = defaultUpstreamResponseHeader
	}
	if cfg.Security.MaxRequestBodyBytes == 0 {
		cfg.Security.MaxRequestBodyBytes = defaultMaxRequestBodyBytes
	}
}

func (cfg *Config) Validate() error {
	if strings.TrimSpace(cfg.ListenAddress) == "" {
		return errors.New("listen_address is required")
	}
	cfg.TLS.CertFile = strings.TrimSpace(cfg.TLS.CertFile)
	cfg.TLS.KeyFile = strings.TrimSpace(cfg.TLS.KeyFile)
	if cfg.TLS.Enabled() {
		if cfg.TLS.CertFile == "" {
			return errors.New("tls.cert_file is required when TLS is enabled")
		}
		if cfg.TLS.KeyFile == "" {
			return errors.New("tls.key_file is required when TLS is enabled")
		}
	}
	if len(cfg.Routes) == 0 {
		return errors.New("at least one route is required")
	}

	seenRoutes := make(map[string]struct{}, len(cfg.Routes))
	for i := range cfg.Routes {
		route := &cfg.Routes[i]
		route.PublicHost = normalizeHost(route.PublicHost)
		if route.PublicHost == "" {
			return fmt.Errorf("routes[%d].public_host is required", i)
		}
		if strings.Contains(route.PublicHost, "/") || strings.Contains(route.PublicHost, "://") {
			return fmt.Errorf("routes[%d].public_host must be a host, not a URL", i)
		}

		if err := validateHTTPURL(route.UpstreamBase, fmt.Sprintf("routes[%d].upstream_base", i)); err != nil {
			return err
		}
		if route.AllowedPathPrefix == "" {
			return fmt.Errorf("routes[%d].allowed_path_prefix is required", i)
		}
		if !strings.HasPrefix(route.AllowedPathPrefix, "/") {
			return fmt.Errorf("routes[%d].allowed_path_prefix must start with /", i)
		}
		if len(route.AllowedMethods) == 0 {
			return fmt.Errorf("routes[%d].allowed_methods must not be empty", i)
		}
		normalizedMethods, err := normalizeMethods(route.AllowedMethods)
		if err != nil {
			return fmt.Errorf("routes[%d].allowed_methods: %w", i, err)
		}
		route.AllowedMethods = normalizedMethods

		key := route.PublicHost + "\x00" + route.AllowedPathPrefix
		if _, ok := seenRoutes[key]; ok {
			return fmt.Errorf("duplicate route for host %q and path prefix %q", route.PublicHost, route.AllowedPathPrefix)
		}
		seenRoutes[key] = struct{}{}
	}

	if err := validateHTTPURL(cfg.OutboundHTTPProxy.URL, "outbound_http_proxy.url"); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.OutboundHTTPProxy.Username) == "" {
		return errors.New("outbound_http_proxy.username is required")
	}
	if cfg.OutboundHTTPProxy.Password == "" {
		return errors.New("outbound_http_proxy.password is required")
	}
	if cfg.Security.MaxRequestBodyBytes < 0 {
		return errors.New("security.max_request_body_bytes must not be negative")
	}

	return validateTimeouts(cfg.Timeouts)
}

func validateHTTPURL(rawURL, field string) error {
	if strings.TrimSpace(rawURL) == "" {
		return fmt.Errorf("%s is required", field)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%s is invalid: %w", field, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s must use http or https scheme", field)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", field)
	}
	return nil
}

func validateTimeouts(timeouts Timeouts) error {
	values := map[string]time.Duration{
		"timeouts.read_header_timeout":      timeouts.ReadHeader,
		"timeouts.read_timeout":             timeouts.Read,
		"timeouts.write_timeout":            timeouts.Write,
		"timeouts.idle_timeout":             timeouts.Idle,
		"timeouts.upstream_response_header": timeouts.UpstreamResponseHeader,
	}
	for name, value := range values {
		if value <= 0 {
			return fmt.Errorf("%s must be greater than zero", name)
		}
	}
	if timeouts.ReadHeader > timeouts.Read {
		return errors.New("timeouts.read_header_timeout must not be greater than timeouts.read_timeout")
	}
	return nil
}

func normalizeMethods(methods []string) ([]string, error) {
	seen := make(map[string]struct{}, len(methods))
	normalized := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			return nil, errors.New("method must not be empty")
		}
		if !isHTTPToken(method) {
			return nil, fmt.Errorf("%q is not a valid HTTP method", method)
		}
		if _, ok := seen[method]; ok {
			return nil, fmt.Errorf("duplicate method %q", method)
		}
		seen[method] = struct{}{}
		normalized = append(normalized, method)
	}
	return normalized, nil
}

func isHTTPToken(value string) bool {
	for _, r := range value {
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func parseDurationValue(raw string, field string) (time.Duration, error) {
	value, err := parseString(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s is invalid: %w", field, err)
	}
	return duration, nil
}

func parseInt64Value(raw string, field string) (int64, error) {
	value, err := parseString(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", field)
	}
	return parsed, nil
}
