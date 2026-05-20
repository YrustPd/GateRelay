package config

import (
	"bufio"
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

type yamlLine struct {
	number int
	indent int
	text   string
}

func parseYAMLConfig(data []byte) (*Config, error) {
	lines, err := scanYAMLLines(data)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}
	seenTopLevel := make(map[string]struct{})
	for i := 0; i < len(lines); {
		line := lines[i]
		if line.indent != 0 {
			return nil, line.errorf("top-level key must not be indented")
		}

		key, value, err := splitKeyValue(line.text)
		if err != nil {
			return nil, line.wrap(err)
		}
		if _, ok := seenTopLevel[key]; ok {
			return nil, line.errorf("duplicate top-level key %q", key)
		}
		seenTopLevel[key] = struct{}{}

		switch key {
		case "listen_address":
			if value == "" {
				return nil, line.errorf("listen_address requires a value")
			}
			cfg.ListenAddress, err = parseString(value)
			if err != nil {
				return nil, line.wrap(err)
			}
			i++
		case "tls":
			if value != "" {
				return nil, line.errorf("tls must be a block map")
			}
			cfg.TLS, i, err = parseTLS(lines, i+1)
			if err != nil {
				return nil, err
			}
		case "routes":
			if value != "" {
				return nil, line.errorf("routes must be a block list")
			}
			cfg.Routes, i, err = parseRoutes(lines, i+1)
			if err != nil {
				return nil, err
			}
		case "outbound_http_proxy":
			if value != "" {
				return nil, line.errorf("outbound_http_proxy must be a block map")
			}
			cfg.OutboundHTTPProxy, i, err = parseProxy(lines, i+1)
			if err != nil {
				return nil, err
			}
		case "timeouts":
			if value != "" {
				return nil, line.errorf("timeouts must be a block map")
			}
			cfg.Timeouts, i, err = parseTimeouts(lines, i+1)
			if err != nil {
				return nil, err
			}
		case "security":
			if value != "" {
				return nil, line.errorf("security must be a block map")
			}
			cfg.Security, i, err = parseSecurity(lines, i+1)
			if err != nil {
				return nil, err
			}
		default:
			return nil, line.errorf("unknown top-level key %q", key)
		}
	}

	return cfg, nil
}

func scanYAMLLines(data []byte) ([]yamlLine, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, 1024*1024)

	var lines []yamlLine
	for number := 1; scanner.Scan(); number++ {
		raw := strings.TrimRight(scanner.Text(), " \r")
		withoutComment := stripYAMLComment(raw)
		if strings.TrimSpace(withoutComment) == "" {
			continue
		}

		indent := 0
		for indent < len(withoutComment) {
			switch withoutComment[indent] {
			case ' ':
				indent++
			case '\t':
				return nil, yamlLine{number: number}.errorf("tabs are not supported for indentation")
			default:
				goto doneIndent
			}
		}
	doneIndent:
		if indent%2 != 0 {
			return nil, yamlLine{number: number}.errorf("indentation must use multiples of two spaces")
		}

		lines = append(lines, yamlLine{
			number: number,
			indent: indent,
			text:   strings.TrimSpace(withoutComment),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func parseRoutes(lines []yamlLine, start int) ([]Route, int, error) {
	var routes []Route
	i := start
	for i < len(lines) && lines[i].indent > 0 {
		line := lines[i]
		if line.indent != 2 {
			return nil, i, line.errorf("route entries must be indented two spaces")
		}
		if line.text != "-" && !strings.HasPrefix(line.text, "- ") {
			return nil, i, line.errorf("route entry must start with -")
		}

		route := Route{}
		seen := make(map[string]struct{})
		itemText := strings.TrimSpace(strings.TrimPrefix(line.text, "-"))
		if itemText != "" {
			key, value, err := splitKeyValue(itemText)
			if err != nil {
				return nil, i, line.wrap(err)
			}
			if err := applyRouteField(&route, seen, key, value, line); err != nil {
				return nil, i, err
			}
		}

		i++
		for i < len(lines) && lines[i].indent > 2 {
			fieldLine := lines[i]
			if fieldLine.indent != 4 {
				return nil, i, fieldLine.errorf("route fields must be indented four spaces")
			}
			key, value, err := splitKeyValue(fieldLine.text)
			if err != nil {
				return nil, i, fieldLine.wrap(err)
			}
			if key == "allowed_methods" && value == "" {
				methods, next, err := parseStringSequence(lines, i+1, fieldLine.indent)
				if err != nil {
					return nil, i, err
				}
				if err := setRouteMethods(&route, seen, methods, fieldLine); err != nil {
					return nil, i, err
				}
				i = next
				continue
			}
			if err := applyRouteField(&route, seen, key, value, fieldLine); err != nil {
				return nil, i, err
			}
			i++
		}

		routes = append(routes, route)
	}
	return routes, i, nil
}

func parseTLS(lines []yamlLine, start int) (TLSConfig, int, error) {
	tls := TLSConfig{configured: true}
	i := start
	seen := make(map[string]struct{})
	for i < len(lines) && lines[i].indent > 0 {
		line := lines[i]
		if line.indent != 2 {
			return tls, i, line.errorf("tls fields must be indented two spaces")
		}
		key, value, err := splitKeyValue(line.text)
		if err != nil {
			return tls, i, line.wrap(err)
		}
		if _, ok := seen[key]; ok {
			return tls, i, line.errorf("duplicate tls field %q", key)
		}
		seen[key] = struct{}{}

		switch key {
		case "cert_file":
			tls.CertFile, err = requireString(value, key)
		case "key_file":
			tls.KeyFile, err = requireString(value, key)
		default:
			return tls, i, line.errorf("unknown tls field %q", key)
		}
		if err != nil {
			return tls, i, line.wrap(err)
		}
		i++
	}
	return tls, i, nil
}

func applyRouteField(route *Route, seen map[string]struct{}, key, value string, line yamlLine) error {
	if _, ok := seen[key]; ok {
		return line.errorf("duplicate route field %q", key)
	}

	switch key {
	case "public_host":
		parsed, err := requireString(value, key)
		if err != nil {
			return line.wrap(err)
		}
		route.PublicHost = parsed
	case "upstream_base":
		parsed, err := requireString(value, key)
		if err != nil {
			return line.wrap(err)
		}
		route.UpstreamBase = parsed
	case "allowed_path_prefix":
		parsed, err := requireString(value, key)
		if err != nil {
			return line.wrap(err)
		}
		route.AllowedPathPrefix = parsed
	case "allowed_methods":
		methods, err := parseStringList(value)
		if err != nil {
			return line.wrap(fmt.Errorf("allowed_methods must be a list: %w", err))
		}
		return setRouteMethods(route, seen, methods, line)
	case "pass_query_string":
		parsed, err := parseBool(value)
		if err != nil {
			return line.wrap(fmt.Errorf("pass_query_string: %w", err))
		}
		route.PassQueryString = parsed
	default:
		return line.errorf("unknown route field %q", key)
	}

	seen[key] = struct{}{}
	return nil
}

func setRouteMethods(route *Route, seen map[string]struct{}, methods []string, line yamlLine) error {
	if _, ok := seen["allowed_methods"]; ok {
		return line.errorf("duplicate route field %q", "allowed_methods")
	}
	route.AllowedMethods = methods
	seen["allowed_methods"] = struct{}{}
	return nil
}

func parseProxy(lines []yamlLine, start int) (OutboundHTTPProxy, int, error) {
	var proxy OutboundHTTPProxy
	i := start
	seen := make(map[string]struct{})
	for i < len(lines) && lines[i].indent > 0 {
		line := lines[i]
		if line.indent != 2 {
			return proxy, i, line.errorf("outbound_http_proxy fields must be indented two spaces")
		}
		key, value, err := splitKeyValue(line.text)
		if err != nil {
			return proxy, i, line.wrap(err)
		}
		if _, ok := seen[key]; ok {
			return proxy, i, line.errorf("duplicate outbound_http_proxy field %q", key)
		}
		seen[key] = struct{}{}

		switch key {
		case "url":
			proxy.URL, err = requireString(value, key)
		case "username":
			proxy.Username, err = requireString(value, key)
		case "password":
			proxy.Password, err = requireString(value, key)
		default:
			return proxy, i, line.errorf("unknown outbound_http_proxy field %q", key)
		}
		if err != nil {
			return proxy, i, line.wrap(err)
		}
		i++
	}
	return proxy, i, nil
}

func parseTimeouts(lines []yamlLine, start int) (Timeouts, int, error) {
	var timeouts Timeouts
	i := start
	seen := make(map[string]struct{})
	for i < len(lines) && lines[i].indent > 0 {
		line := lines[i]
		if line.indent != 2 {
			return timeouts, i, line.errorf("timeouts fields must be indented two spaces")
		}
		key, value, err := splitKeyValue(line.text)
		if err != nil {
			return timeouts, i, line.wrap(err)
		}
		field := canonicalTimeoutField(key)
		if field == "" {
			return timeouts, i, line.errorf("unknown timeouts field %q", key)
		}
		if _, ok := seen[field]; ok {
			return timeouts, i, line.errorf("duplicate timeouts field %q", key)
		}
		seen[field] = struct{}{}

		switch field {
		case "read_header_timeout":
			timeouts.ReadHeader, err = parseDurationValue(value, "timeouts.read_header_timeout")
		case "read_timeout":
			timeouts.Read, err = parseDurationValue(value, "timeouts.read_timeout")
		case "write_timeout":
			timeouts.Write, err = parseDurationValue(value, "timeouts.write_timeout")
		case "idle_timeout":
			timeouts.Idle, err = parseDurationValue(value, "timeouts.idle_timeout")
		case "upstream_response_header":
			timeouts.UpstreamResponseHeader, err = parseDurationValue(value, "timeouts.upstream_response_header")
		}
		if err != nil {
			return timeouts, i, err
		}
		i++
	}
	return timeouts, i, nil
}

func canonicalTimeoutField(key string) string {
	switch key {
	case "read_header", "read_header_timeout":
		return "read_header_timeout"
	case "read", "read_timeout":
		return "read_timeout"
	case "write", "write_timeout":
		return "write_timeout"
	case "idle", "idle_timeout":
		return "idle_timeout"
	case "upstream_response_header":
		return "upstream_response_header"
	default:
		return ""
	}
}

func parseSecurity(lines []yamlLine, start int) (Security, int, error) {
	var security Security
	i := start
	seen := make(map[string]struct{})
	for i < len(lines) && lines[i].indent > 0 {
		line := lines[i]
		if line.indent != 2 {
			return security, i, line.errorf("security fields must be indented two spaces")
		}
		key, value, err := splitKeyValue(line.text)
		if err != nil {
			return security, i, line.wrap(err)
		}
		if _, ok := seen[key]; ok {
			return security, i, line.errorf("duplicate security field %q", key)
		}
		seen[key] = struct{}{}

		switch key {
		case "reject_empty_host":
			security.RejectEmptyHost, err = parseBool(value)
		case "hide_token_in_logs":
			security.HideTokenInLogs, err = parseBool(value)
		case "max_request_body_bytes":
			security.MaxRequestBodyBytes, err = parseInt64Value(value, "security.max_request_body_bytes")
		default:
			return security, i, line.errorf("unknown security field %q", key)
		}
		if err != nil {
			return security, i, line.wrap(err)
		}
		i++
	}
	return security, i, nil
}

func parseStringSequence(lines []yamlLine, start int, parentIndent int) ([]string, int, error) {
	var values []string
	i := start
	expectedIndent := parentIndent + 2
	for i < len(lines) && lines[i].indent > parentIndent {
		line := lines[i]
		if line.indent != expectedIndent || line.text == "-" || !strings.HasPrefix(line.text, "- ") {
			return nil, i, line.errorf("expected list item")
		}
		value, err := parseString(strings.TrimSpace(strings.TrimPrefix(line.text, "-")))
		if err != nil {
			return nil, i, line.wrap(err)
		}
		values = append(values, value)
		i++
	}
	if len(values) == 0 {
		return nil, i, yamlLine{number: lines[start-1].number}.errorf("expected at least one list item")
	}
	return values, i, nil
}

func splitKeyValue(text string) (string, string, error) {
	index := strings.IndexByte(text, ':')
	if index < 1 {
		return "", "", fmt.Errorf("expected key: value")
	}
	key := strings.TrimSpace(text[:index])
	value := strings.TrimSpace(text[index+1:])
	if key == "" {
		return "", "", fmt.Errorf("key must not be empty")
	}
	return key, value, nil
}

func requireString(raw string, field string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%s requires a value", field)
	}
	return parseString(raw)
}

func parseString(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", nil
	}
	if strings.HasPrefix(value, "\"") {
		if !strings.HasSuffix(value, "\"") {
			return "", fmt.Errorf("unterminated double-quoted string")
		}
		return strconv.Unquote(value)
	}
	if strings.HasPrefix(value, "'") {
		if !strings.HasSuffix(value, "'") {
			return "", fmt.Errorf("unterminated single-quoted string")
		}
		return strings.ReplaceAll(value[1:len(value)-1], "''", "'"), nil
	}
	return value, nil
}

func parseBool(raw string) (bool, error) {
	value, err := requireString(raw, "boolean")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(value) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("expected true or false")
	}
}

func parseStringList(raw string) ([]string, error) {
	value := strings.TrimSpace(raw)
	if !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
		return nil, fmt.Errorf("expected [value, ...]")
	}
	body := strings.TrimSpace(value[1 : len(value)-1])
	if body == "" {
		return nil, nil
	}

	parts, err := splitCommaAware(body)
	if err != nil {
		return nil, err
	}
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		parsed, err := parseString(part)
		if err != nil {
			return nil, err
		}
		values = append(values, parsed)
	}
	return values, nil
}

func splitCommaAware(value string) ([]string, error) {
	var parts []string
	start := 0
	inSingle := false
	inDouble := false
	escaped := false
	for i, r := range value {
		if inDouble {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == '"' {
				inDouble = false
			}
			continue
		}
		if inSingle {
			if r == '\'' {
				inSingle = false
			}
			continue
		}
		switch r {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case ',':
			parts = append(parts, strings.TrimSpace(value[start:i]))
			start = i + 1
		}
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quoted string")
	}
	parts = append(parts, strings.TrimSpace(value[start:]))
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("empty list item")
		}
	}
	return parts, nil
}

func stripYAMLComment(line string) string {
	inSingle := false
	inDouble := false
	escaped := false
	for i, r := range line {
		if inDouble {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			if r == '"' {
				inDouble = false
			}
			continue
		}
		if inSingle {
			if r == '\'' {
				inSingle = false
			}
			continue
		}
		switch r {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '#':
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return strings.TrimRight(line[:i], " ")
			}
		}
	}
	return line
}

func (line yamlLine) errorf(format string, args ...any) error {
	return fmt.Errorf("line %d: %s", line.number, fmt.Sprintf(format, args...))
}

func (line yamlLine) wrap(err error) error {
	return fmt.Errorf("line %d: %w", line.number, err)
}
