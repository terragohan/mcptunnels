# Troubleshooting

Real failure modes seen while running tunneld.

## Cloudflare orange-cloud → 521 (or ACME failures)

If your domain is proxied through Cloudflare (orange cloud), tunneld can't
complete the TLS-ALPN-01 challenge and clients may see 521 errors. Set the
DNS record to **DNS only** (grey cloud) so port 443 reaches tunneld
directly.

## ACME `invalidContact`

Let's Encrypt rejects placeholder contact addresses. Set a real email in
`tunneld.yaml` under `tls.acme.email` and restart tunneld.

## Stale binary after re-running the setup script

`scripts/setup-ubuntu-24.04.sh` rebuilds into `~/tunneld/bin` but does not
restart the service. Check timestamps (`ls -l ~/tunneld/bin`) and restart:

```sh
supervisorctl -c ~/tunneld/supervisord.conf restart tunneld
```

## Nothing listens on :80

By design. ACME uses TLS-ALPN-01 over 443 only; use `https://` URLs and open
port 443. Do not add a port-80 redirect expecting tunneld to serve it.

## tunneld fails to start with a config error

The config loader uses strict YAML decoding (`KnownFields`): any unknown or
misspelled key in `tunneld.yaml` fails startup with an error naming the key.
Compare your file against the reference in
[docs/self-hosting.md](self-hosting.md#configuration-reference-tunneld-yaml).
