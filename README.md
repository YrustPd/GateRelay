<p align="center">
  <img src="assets/gaterelay.svg" width="110" alt="GateRelay logo">
</p>

<h1 align="center">GateRelay</h1>

<p align="center">
  <strong>A strict domain-gated reverse relay for controlled outbound HTTP proxy routing.</strong>
</p>
<p align="center">
  <a href="LICENSE"><img alt="License: AGPL-3.0" src="https://img.shields.io/badge/license-AGPL--3.0-111111"></a>
  <img alt="Go 1.22+" src="https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go&logoColor=white">
  <img alt="Status: stable" src="https://img.shields.io/badge/status-stable-111111">
  <img alt="Build status" src="https://img.shields.io/badge/build-passing-238636">
  <a href="https://t.me/PdYrust"><img alt="Telegram channel" src="https://img.shields.io/badge/Telegram-%40PdYrust-229ED9?logo=telegram&logoColor=white"></a>
</p>


## What is GateRelay?

GateRelay is a small Go HTTPS reverse relay for controlled access to fixed upstream services through a paid authenticated HTTP proxy. It accepts requests only for configured public hosts and configured path prefixes, then relays approved traffic to upstream targets defined in config.

GateRelay is intentionally not an open proxy.

## Why GateRelay?

GateRelay is built for deployments where users need access through a controlled public domain while outbound traffic must leave through a fixed authenticated HTTP proxy. The service keeps that setup narrow: every accepted host, path prefix, method, upstream, and proxy credential is configured by the operator.

## How it works

1. GateRelay receives an HTTP or HTTPS request.
2. `/healthz` is answered locally.
3. The request `Host` must match a configured `public_host`.
4. The request path must match a configured `allowed_path_prefix`, such as `/sub/`.
5. The method must be listed in `allowed_methods`.
6. The dynamic token after the allowed prefix must not be empty.
7. Only after local validation passes, GateRelay builds the upstream URL from `upstream_base` and the incoming path.
8. The request is sent through the configured authenticated outbound HTTP proxy.

Unknown hosts, invalid paths, invalid methods, and empty tokens are rejected locally before the outbound proxy is touched.

## Security model

- Upstream targets come only from configuration, never from user input.
- The paid outbound HTTP proxy is used only after strict local validation passes.
- Hop-by-hop headers are stripped from forwarded requests and returned responses.
- `Proxy-Authorization` is never forwarded to the upstream server or returned to clients.
- Redirects from upstream are returned to the client instead of being followed automatically.
- Full subscription tokens are hidden from relay error logs when `security.hide_token_in_logs` is enabled.

## Configuration

Example:

```yaml
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

security:
  reject_empty_host: true
  hide_token_in_logs: true
  max_request_body_bytes: 1048576
```

See [configs/production.example.yaml](configs/production.example.yaml) for a fuller production example.

## Running locally

Use the development sample without TLS:

```sh
go run ./cmd/gaterelay -config config.example.yaml
```

Validate a config without serving:

```sh
go run ./cmd/gaterelay -config configs/production.example.yaml -check-config
```

## Production deployment

GateRelay can serve HTTPS directly with `tls.cert_file` and `tls.key_file`. It does not require Docker or external runtime services.

A common production flow is to build the binary elsewhere, copy it to the server, install a config file under `/etc/gaterelay/config.yaml`, validate it with `-check-config`, then start GateRelay under systemd. This makes offline deployment straightforward after the binary and config are prepared.

See [docs/deploy-notes.md](docs/deploy-notes.md) for compact install notes.

## Systemd

A service template is provided at [deploy/gaterelay.service](deploy/gaterelay.service).

The unit runs:

```sh
/usr/local/bin/gaterelay -config /etc/gaterelay/config.yaml
```

Keep proxy credentials in the config file, not in the systemd unit or command line.

## Build

```sh
go test ./...
go build -o gaterelay ./cmd/gaterelay
```

The project uses only the Go standard library.

## License

GateRelay is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
