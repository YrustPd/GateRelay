package server

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gaterelay/internal/config"
)

func TestRejectedRequestsDoNotUseProxy(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
		host   string
	}{
		{
			name:   "unknown host",
			method: http.MethodGet,
			target: "https://unknown.example.com/sub/token",
		},
		{
			name:   "invalid path",
			method: http.MethodGet,
			target: "https://public.example.com/private/token",
		},
		{
			name:   "invalid method",
			method: http.MethodDelete,
			target: "https://public.example.com/sub/token",
		},
		{
			name:   "empty token",
			method: http.MethodGet,
			target: "https://public.example.com/sub/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := newRecordingProxy(t)
			app := newTestServer(t, testRoute("http://upstream.example.net", true), proxy.URL())

			req := httptest.NewRequest(tt.method, tt.target, nil)
			if tt.host != "" {
				req.Host = tt.host
			}
			rec := httptest.NewRecorder()

			app.ServeHTTP(rec, req)

			if rec.Code == http.StatusOK {
				t.Fatalf("status = %d, want rejection", rec.Code)
			}
			if got := proxy.Count(); got != 0 {
				t.Fatalf("proxy requests = %d, want 0", got)
			}
		})
	}
}

func TestHealthzNeverUsesProxy(t *testing.T) {
	proxy := newRecordingProxy(t)
	app := newTestServer(t, testRoute("http://upstream.example.net", true), proxy.URL())

	req := httptest.NewRequest(http.MethodGet, "https://health.example.com/healthz", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != "ok\n" {
		t.Fatalf("body = %q, want ok", got)
	}
	if got := proxy.Count(); got != 0 {
		t.Fatalf("proxy requests = %d, want 0", got)
	}
}

func TestValidRequestBuildsCorrectUpstreamURL(t *testing.T) {
	var gotRequestURI string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotRequestURI = req.URL.RequestURI()
		_, _ = w.Write([]byte("upstream ok"))
	}))
	defer upstream.Close()

	proxy := newRecordingProxy(t)
	app := newTestServer(t, testRoute(upstream.URL, true), proxy.URL())

	req := httptest.NewRequest(http.MethodGet, "https://public.example.com/sub/token?plan=premium", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if gotRequestURI != "/sub/token?plan=premium" {
		t.Fatalf("upstream request URI = %q", gotRequestURI)
	}

	proxyReqs := proxy.Requests()
	if len(proxyReqs) != 1 {
		t.Fatalf("proxy requests = %d, want 1", len(proxyReqs))
	}
	if proxyReqs[0].Target != upstream.URL+"/sub/token?plan=premium" {
		t.Fatalf("proxy target = %q", proxyReqs[0].Target)
	}
	if proxyReqs[0].ProxyAuthorization == "" {
		t.Fatal("proxy did not receive Proxy-Authorization")
	}
	if rec.Body.String() != "upstream ok" {
		t.Fatalf("response body = %q", rec.Body.String())
	}
}

func TestPassQueryStringFalseDropsQuery(t *testing.T) {
	var gotRequestURI string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotRequestURI = req.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	proxy := newRecordingProxy(t)
	app := newTestServer(t, testRoute(upstream.URL, false), proxy.URL())

	req := httptest.NewRequest(http.MethodGet, "https://public.example.com/sub/token?plan=premium", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if gotRequestURI != "/sub/token" {
		t.Fatalf("upstream request URI = %q, want query dropped", gotRequestURI)
	}
}

func TestPassQueryStringTruePreservesQuery(t *testing.T) {
	var gotRequestURI string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotRequestURI = req.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	proxy := newRecordingProxy(t)
	app := newTestServer(t, testRoute(upstream.URL, true), proxy.URL())

	req := httptest.NewRequest(http.MethodGet, "https://public.example.com/sub/token?plan=premium", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rec.Code)
	}
	if gotRequestURI != "/sub/token?plan=premium" {
		t.Fatalf("upstream request URI = %q, want query preserved", gotRequestURI)
	}
}

func TestHopByHopHeadersAreNotForwarded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		for _, key := range []string{"Connection", "Keep-Alive", "Proxy-Authorization", "X-Hop"} {
			if value := req.Header.Get(key); value != "" {
				t.Fatalf("upstream received %s = %q", key, value)
			}
		}
		w.Header().Set("Connection", "close")
		w.Header().Set("X-Upstream", "ok")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxy := newRecordingProxy(t)
	app := newTestServer(t, testRoute(upstream.URL, true), proxy.URL())

	req := httptest.NewRequest(http.MethodGet, "https://public.example.com/sub/token", nil)
	req.Header.Set("Connection", "keep-alive, X-Hop")
	req.Header.Set("Keep-Alive", "timeout=5")
	req.Header.Set("Proxy-Authorization", "Basic REDACTED")
	req.Header.Set("X-Hop", "remove")
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if value := rec.Header().Get("Connection"); value != "" {
		t.Fatalf("client received Connection = %q", value)
	}
	if value := rec.Header().Get("X-Upstream"); value != "ok" {
		t.Fatalf("client received X-Upstream = %q", value)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var upstreamRequests int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&upstreamRequests, 1)
		http.Redirect(w, req, "/final", http.StatusFound)
	}))
	defer upstream.Close()

	proxy := newRecordingProxy(t)
	app := newTestServer(t, testRoute(upstream.URL, true), proxy.URL())

	req := httptest.NewRequest(http.MethodGet, "https://public.example.com/sub/token", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := atomic.LoadInt32(&upstreamRequests); got != 1 {
		t.Fatalf("upstream requests = %d, want 1", got)
	}
	if got := proxy.Count(); got != 1 {
		t.Fatalf("proxy requests = %d, want 1", got)
	}
	if location := rec.Header().Get("Location"); location != "/final" {
		t.Fatalf("Location = %q", location)
	}
}

func TestHideTokenInLogsSuppressesTokenInRelayErrors(t *testing.T) {
	proxy := httptest.NewServer(http.NotFoundHandler())
	proxyURL := proxy.URL
	proxy.Close()

	var logs bytes.Buffer
	app, err := New(&config.Config{
		ListenAddress: ":0",
		Routes:        []config.Route{testRoute("http://upstream.example.net", true)},
		OutboundHTTPProxy: config.OutboundHTTPProxy{
			URL:      proxyURL,
			Username: "YOUR_PROXY_USERNAME",
			Password: "YOUR_PROXY_PASSWORD",
		},
		Timeouts: config.Timeouts{
			ReadHeader:             5 * time.Second,
			Read:                   15 * time.Second,
			Write:                  30 * time.Second,
			Idle:                   60 * time.Second,
			UpstreamResponseHeader: 5 * time.Second,
		},
		Security: config.Security{
			RejectEmptyHost:     true,
			HideTokenInLogs:     true,
			MaxRequestBodyBytes: 1 << 20,
		},
	}, log.New(&logs, "", 0))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://public.example.com/sub/YOUR_SUBSCRIPTION_TOKEN", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if strings.Contains(logs.String(), "YOUR_SUBSCRIPTION_TOKEN") {
		t.Fatalf("logs leaked token: %q", logs.String())
	}
	if !strings.Contains(logs.String(), "/sub/<redacted>") {
		t.Fatalf("logs = %q, want redacted path", logs.String())
	}
}

func newTestServer(t *testing.T, route config.Route, proxyURL string) *Server {
	t.Helper()

	app, err := New(&config.Config{
		ListenAddress: ":0",
		Routes:        []config.Route{route},
		OutboundHTTPProxy: config.OutboundHTTPProxy{
			URL:      proxyURL,
			Username: "YOUR_PROXY_USERNAME",
			Password: "YOUR_PROXY_PASSWORD",
		},
		Timeouts: config.Timeouts{
			ReadHeader:             5 * time.Second,
			Read:                   15 * time.Second,
			Write:                  30 * time.Second,
			Idle:                   60 * time.Second,
			UpstreamResponseHeader: 5 * time.Second,
		},
		Security: config.Security{
			RejectEmptyHost:     true,
			HideTokenInLogs:     true,
			MaxRequestBodyBytes: 1 << 20,
		},
	}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return app
}

func testRoute(upstreamBase string, passQueryString bool) config.Route {
	return config.Route{
		PublicHost:        "public.example.com",
		UpstreamBase:      upstreamBase,
		AllowedPathPrefix: "/sub/",
		AllowedMethods:    []string{http.MethodGet, http.MethodPost},
		PassQueryString:   passQueryString,
	}
}

type proxyRequest struct {
	Target             string
	ProxyAuthorization string
}

type recordingProxy struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []proxyRequest
}

func newRecordingProxy(t *testing.T) *recordingProxy {
	t.Helper()

	proxy := &recordingProxy{}
	proxy.server = httptest.NewServer(http.HandlerFunc(proxy.handle))
	t.Cleanup(proxy.server.Close)
	return proxy
}

func (proxy *recordingProxy) URL() string {
	return proxy.server.URL
}

func (proxy *recordingProxy) Count() int {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	return len(proxy.requests)
}

func (proxy *recordingProxy) Requests() []proxyRequest {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()

	requests := make([]proxyRequest, len(proxy.requests))
	copy(requests, proxy.requests)
	return requests
}

func (proxy *recordingProxy) handle(w http.ResponseWriter, req *http.Request) {
	proxy.record(req)

	target := *req.URL
	if target.Scheme == "" || target.Host == "" {
		http.Error(w, "proxy target must be absolute", http.StatusBadGateway)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "read proxy request body", http.StatusBadGateway)
		return
	}
	outReq, err := http.NewRequestWithContext(req.Context(), req.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "build proxy request", http.StatusBadGateway)
		return
	}
	copySafeHeaders(outReq.Header, req.Header)
	outReq.Header.Del("Proxy-Authorization")
	outReq.ContentLength = int64(len(body))

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "proxy upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copySafeHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (proxy *recordingProxy) record(req *http.Request) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()

	target := ""
	if req.URL != nil {
		target = req.URL.String()
	}
	if parsed, err := url.Parse(target); err == nil {
		target = parsed.String()
	}
	proxy.requests = append(proxy.requests, proxyRequest{
		Target:             target,
		ProxyAuthorization: req.Header.Get("Proxy-Authorization"),
	})
}
