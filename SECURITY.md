# Security Policy

GateRelay handles routing rules, proxy credentials, TLS paths, and subscription-style tokens. Please do not disclose security vulnerabilities in public issues or discussions.

## Reporting a vulnerability

Use GitHub private vulnerability reporting if it is enabled for this repository. If it is not available, contact the maintainers privately before sharing details.

Do not include these in public reports:

- Proxy username or password
- Full subscription tokens
- Private TLS keys
- Exploit details for an unpatched vulnerability
- Real production logs containing sensitive hosts, IPs, or credentials

## Supported versions

Security fixes are expected to target the latest released version and the main development branch.

## Security model reminders

GateRelay must reject unknown hosts, invalid paths, invalid methods, and empty tokens locally before using the outbound HTTP proxy. Upstream targets must come from config, never from user input.
