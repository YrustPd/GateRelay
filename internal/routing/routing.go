package routing

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"gaterelay/internal/config"
)

type RejectReason string

const (
	RejectUnknownHost      RejectReason = "unknown_host"
	RejectPathNotAllowed   RejectReason = "path_not_allowed"
	RejectMethodNotAllowed RejectReason = "method_not_allowed"
	RejectEmptyToken       RejectReason = "empty_token"
)

type MatchError struct {
	Reason         RejectReason
	AllowedMethods []string
}

func (err *MatchError) Error() string {
	return string(err.Reason)
}

type Router struct {
	routesByHost map[string][]config.Route
}

func New(routes []config.Route) (*Router, error) {
	if len(routes) == 0 {
		return nil, fmt.Errorf("at least one route is required")
	}

	routesByHost := make(map[string][]config.Route)
	for _, route := range routes {
		host := NormalizeHost(route.PublicHost)
		if host == "" {
			return nil, fmt.Errorf("route public_host is required")
		}
		routesByHost[host] = append(routesByHost[host], route)
	}

	for host := range routesByHost {
		sort.SliceStable(routesByHost[host], func(i, j int) bool {
			return len(routesByHost[host][i].AllowedPathPrefix) > len(routesByHost[host][j].AllowedPathPrefix)
		})
	}

	return &Router{routesByHost: routesByHost}, nil
}

func (router *Router) Match(req *http.Request) (config.Route, *MatchError) {
	host := NormalizeHost(req.Host)
	routes := router.routesByHost[host]
	if len(routes) == 0 {
		return config.Route{}, &MatchError{Reason: RejectUnknownHost}
	}

	path := RequestPath(req)
	for _, route := range routes {
		if !PathPrefixMatches(path, route.AllowedPathPrefix) {
			continue
		}
		if !HasDynamicToken(path, route.AllowedPathPrefix) {
			return config.Route{}, &MatchError{Reason: RejectEmptyToken}
		}
		if !methodAllowed(req.Method, route.AllowedMethods) {
			return config.Route{}, &MatchError{
				Reason:         RejectMethodNotAllowed,
				AllowedMethods: append([]string(nil), route.AllowedMethods...),
			}
		}
		return route, nil
	}

	return config.Route{}, &MatchError{Reason: RejectPathNotAllowed}
}

func RequestPath(req *http.Request) string {
	if req.URL == nil {
		return ""
	}
	path := req.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func NormalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

func PathPrefixMatches(path, prefix string) bool {
	if prefix == "/" {
		return strings.HasPrefix(path, "/")
	}
	if path == prefix {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(path, prefix)
	}
	return strings.HasPrefix(path, prefix+"/")
}

func HasDynamicToken(path, prefix string) bool {
	token := ""
	switch {
	case prefix == "/":
		token = strings.TrimPrefix(path, "/")
	case strings.HasSuffix(prefix, "/"):
		token = strings.TrimPrefix(path, prefix)
	case path == prefix:
		token = ""
	default:
		token = strings.TrimPrefix(path, prefix+"/")
	}
	return strings.Trim(token, "/") != ""
}

func methodAllowed(method string, allowed []string) bool {
	method = strings.ToUpper(method)
	for _, candidate := range allowed {
		if method == candidate {
			return true
		}
	}
	return false
}
