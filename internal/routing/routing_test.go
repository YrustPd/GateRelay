package routing

import (
	"net/http/httptest"
	"testing"

	"gaterelay/internal/config"
)

func TestMatchAcceptsKnownHostPathAndMethod(t *testing.T) {
	router := newTestRouter(t)
	req := httptest.NewRequest("GET", "https://public.example.com/v1/users?active=true", nil)
	req.Host = "PUBLIC.EXAMPLE.COM:443"

	route, err := router.Match(req)
	if err != nil {
		t.Fatalf("Match() error = %v", err)
	}
	if route.PublicHost != "public.example.com" {
		t.Fatalf("PublicHost = %q", route.PublicHost)
	}
}

func TestMatchRejectsUnknownHost(t *testing.T) {
	router := newTestRouter(t)
	req := httptest.NewRequest("GET", "https://unknown.example.com/v1/users", nil)

	_, err := router.Match(req)
	if err == nil || err.Reason != RejectUnknownHost {
		t.Fatalf("Match() error = %v, want %s", err, RejectUnknownHost)
	}
}

func TestMatchRejectsPathOutsidePrefix(t *testing.T) {
	router := newTestRouter(t)
	req := httptest.NewRequest("GET", "https://public.example.com/private", nil)

	_, err := router.Match(req)
	if err == nil || err.Reason != RejectPathNotAllowed {
		t.Fatalf("Match() error = %v, want %s", err, RejectPathNotAllowed)
	}
}

func TestMatchRejectsPrefixLookalikePath(t *testing.T) {
	router := newTestRouter(t)
	req := httptest.NewRequest("GET", "https://public.example.com/v10", nil)

	_, err := router.Match(req)
	if err == nil || err.Reason != RejectPathNotAllowed {
		t.Fatalf("Match() error = %v, want %s", err, RejectPathNotAllowed)
	}
}

func TestMatchRejectsEncodedSlashInsidePrefix(t *testing.T) {
	router, err := New([]config.Route{
		{
			PublicHost:        "public.example.com",
			UpstreamBase:      "https://upstream.example.net",
			AllowedPathPrefix: "/sub/",
			AllowedMethods:    []string{"GET"},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest("GET", "https://public.example.com/sub%2Ftoken", nil)
	_, matchErr := router.Match(req)
	if matchErr == nil || matchErr.Reason != RejectPathNotAllowed {
		t.Fatalf("Match() error = %v, want %s", matchErr, RejectPathNotAllowed)
	}
}

func TestMatchRejectsDisallowedMethod(t *testing.T) {
	router := newTestRouter(t)
	req := httptest.NewRequest("DELETE", "https://public.example.com/v1/users", nil)

	_, err := router.Match(req)
	if err == nil || err.Reason != RejectMethodNotAllowed {
		t.Fatalf("Match() error = %v, want %s", err, RejectMethodNotAllowed)
	}
	if len(err.AllowedMethods) != 2 || err.AllowedMethods[0] != "GET" || err.AllowedMethods[1] != "POST" {
		t.Fatalf("AllowedMethods = %#v", err.AllowedMethods)
	}
}

func TestMatchRejectsEmptyDynamicToken(t *testing.T) {
	router, err := New([]config.Route{
		{
			PublicHost:        "public.example.com",
			UpstreamBase:      "https://upstream.example.net",
			AllowedPathPrefix: "/sub/",
			AllowedMethods:    []string{"GET"},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest("GET", "https://public.example.com/sub/", nil)
	_, matchErr := router.Match(req)
	if matchErr == nil || matchErr.Reason != RejectEmptyToken {
		t.Fatalf("Match() error = %v, want %s", matchErr, RejectEmptyToken)
	}
}

func TestMatchUsesMostSpecificRoute(t *testing.T) {
	router, err := New([]config.Route{
		{
			PublicHost:        "public.example.com",
			UpstreamBase:      "https://upstream.example.net",
			AllowedPathPrefix: "/v1",
			AllowedMethods:    []string{"GET"},
		},
		{
			PublicHost:        "public.example.com",
			UpstreamBase:      "https://upstream.example.net/admin",
			AllowedPathPrefix: "/v1/admin",
			AllowedMethods:    []string{"POST"},
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := httptest.NewRequest("GET", "https://public.example.com/v1/admin/users", nil)
	_, matchErr := router.Match(req)
	if matchErr == nil || matchErr.Reason != RejectMethodNotAllowed {
		t.Fatalf("Match() error = %v, want %s", matchErr, RejectMethodNotAllowed)
	}
}

func newTestRouter(t *testing.T) *Router {
	t.Helper()

	router, err := New([]config.Route{
		{
			PublicHost:        "public.example.com",
			UpstreamBase:      "https://upstream.example.net",
			AllowedPathPrefix: "/v1",
			AllowedMethods:    []string{"GET", "POST"},
			PassQueryString:   true,
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return router
}
