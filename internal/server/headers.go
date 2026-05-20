package server

import (
	"net/http"
	"strings"
)

var staticHopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func copySafeHeaders(dst, src http.Header) {
	blocked := blockedHeaders(src)
	for key, values := range src {
		key = http.CanonicalHeaderKey(key)
		if _, ok := blocked[key]; ok {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func blockedHeaders(header http.Header) map[string]struct{} {
	blocked := make(map[string]struct{}, len(staticHopByHopHeaders))
	for _, key := range staticHopByHopHeaders {
		blocked[http.CanonicalHeaderKey(key)] = struct{}{}
	}
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			blocked[http.CanonicalHeaderKey(token)] = struct{}{}
		}
	}
	return blocked
}
