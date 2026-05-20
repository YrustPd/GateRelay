# Contributing

Thanks for considering a contribution to GateRelay.

GateRelay is intentionally small. Changes should preserve the main safety property: the paid outbound HTTP proxy is used only after local host, path, method, and token validation passes.

## Development

Use the standard Go toolchain:

```sh
go test ./...
go vet ./...
go build ./cmd/gaterelay
go run ./cmd/gaterelay -config configs/production.example.yaml -check-config
```

The project currently uses only the Go standard library.

## Pull requests

Keep pull requests focused. Include tests for behavior changes, especially anything touching routing, upstream URL construction, headers, proxy transport, logging, TLS runtime, or deployment files.

Do not include proxy credentials, full subscription tokens, private TLS keys, or real production logs.

## Design expectations

- Do not turn GateRelay into an open proxy.
- Do not accept upstream targets from user input.
- Do not use the outbound proxy before local validation succeeds.
- Prefer the Go standard library.
- Avoid Docker, frameworks, and unnecessary dependencies.
