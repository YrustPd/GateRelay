## Summary

Describe what changed and why.

## Type of change

- [ ] Bug fix
- [ ] Feature
- [ ] Documentation
- [ ] Configuration or deployment
- [ ] Maintenance

## Checklist

- [ ] The change is scoped and easy to review.
- [ ] Core relay behavior is unchanged unless explicitly described.
- [ ] Unknown hosts and invalid paths remain rejected locally.
- [ ] The outbound proxy is still used only after local validation passes.
- [ ] No proxy credentials, full subscription tokens, or private TLS keys are included.

## Tests executed

Paste the commands you ran, for example:

```sh
go test ./...
go vet ./...
go build ./cmd/gaterelay
go run ./cmd/gaterelay -config configs/production.example.yaml -check-config
```

## Security/cost-control impact

Explain whether this changes validation, upstream URL construction, logging, proxy usage, or deployment defaults.

## Notes for maintainers

Mention review risks, follow-up work, or release notes.
