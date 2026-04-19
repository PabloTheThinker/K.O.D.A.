# Hardened MCP server

K.O.D.A. exposes its security tools over the [Model Context Protocol](https://modelcontextprotocol.io/).
There are two transports:

| Transport | Default | Authentication | Use case |
|-----------|---------|----------------|----------|
| **stdio** | yes | trusted (local IPC) | Claude Code, Cursor, single-process |
| **SSE** | no | bearer token (required) + optional mTLS | remote clients, tailnet, CI |

---

## Local dev (stdio)

The default transport is stdio. It is local-IPC — the MCP client spawns `koda mcp` as a child
process and communicates over stdin/stdout. No network port is opened. No authentication is needed.

```json
{
  "mcpServers": {
    "koda": { "command": "koda", "args": ["mcp"] }
  }
}
```

This is the shortest path and the recommended mode for Claude Code, Cursor, and similar hosts
running on the same machine.

---

## Remote SSE with bearer token

Use the SSE transport when the client and server are on separate machines (tailnet, LAN, CI runner).

### Step 1 — generate or supply a token

On first run, K.O.D.A. auto-generates a `secrets.token_urlsafe(32)` token, writes it to
`~/.koda/mcp.toml` (permissions `0600`), and prints it **once** to stderr:

```
┌─────────────────────────────────────────────────────────────┐
│  K.O.D.A. MCP — bearer token (save this, shown only once)  │
│  <your-token-here>                                          │
└─────────────────────────────────────────────────────────────┘
```

To supply your own token, set the environment variable before starting:

```bash
export KODA_MCP_TOKEN="your-long-random-secret"
koda mcp --transport sse --host 0.0.0.0 --port 7655
```

Priority order (highest first):

1. `KODA_MCP_TOKEN` env var
2. `~/.koda/mcp.toml` — `auth.bearer_token`
3. Auto-generated (written to `mcp.toml`)

### Step 2 — start the server

```bash
# Plain HTTP with bearer auth (add TLS for production — see next section)
koda mcp --transport sse --host 0.0.0.0 --port 7655
```

For local-dev only (no auth, loopback-only):

```bash
koda mcp --transport sse --no-auth --host 127.0.0.1 --port 7655
```

`--no-auth` is rejected if `--host` is not a loopback address.

### Step 3 — connect from the client

Every HTTP request must include:

```
Authorization: Bearer <token>
```

The prefix `Bearer` is case-insensitive (RFC 6750). Missing or invalid tokens receive a `401`
response with a generic `{"error":"unauthorized"}` body — the submitted token is never echoed.

Every auth attempt is logged as an audit event:

| Event | Fields |
|-------|--------|
| `mcp.auth.denied` | `remote_addr`, `path`, `reason` |
| `mcp.auth.ok` | `remote_addr`, `path`, `token_fingerprint` (first 8 hex chars of SHA-256) |

Audit events are written to `~/.koda/logs/audit.jsonl` (same log as the rest of K.O.D.A.).
Set `KODA_MCP_NO_AUDIT=1` to suppress them (useful in tests).

---

## mTLS hardening

Use mTLS when running on a hostile network, in a multi-tenant environment, or anywhere bearer
tokens alone are insufficient. mTLS adds a second layer: the server presents its certificate
**and** the client must present a certificate signed by a trusted CA.

### When to use it

- Exposed on a public or semi-public network (not just a tailnet)
- Multi-tenant deployment where different clients must be individually revocable
- Compliance requirements (PCI-DSS, HIPAA) that mandate mutual authentication

### Create a local CA and server certificate with `mkcert`

```bash
# Install mkcert (https://github.com/FiloSottile/mkcert)
mkcert -install                          # create a local CA in the trust store
mkcert koda-server.lan 127.0.0.1 ::1    # server cert — edit SANs as needed
# produces: koda-server.lan+2.pem  koda-server.lan+2-key.pem
```

### Issue a client certificate with `openssl`

```bash
# Generate a client key + CSR
openssl req -newkey rsa:2048 -nodes \
  -keyout client.key \
  -out client.csr \
  -subj "/CN=koda-client"

# Sign with the mkcert CA
# mkcert root CA is typically at:
#   $(mkcert -CAROOT)/rootCA.pem  and  $(mkcert -CAROOT)/rootCA-key.pem
openssl x509 -req -in client.csr \
  -CA "$(mkcert -CAROOT)/rootCA.pem" \
  -CAkey "$(mkcert -CAROOT)/rootCA-key.pem" \
  -CAcreateserial \
  -out client.crt \
  -days 365
```

### Start the server with mTLS

```bash
koda mcp --transport sse \
  --host 0.0.0.0 \
  --port 7655 \
  --tls-cert koda-server.lan+2.pem \
  --tls-key  koda-server.lan+2-key.pem \
  --client-ca "$(mkcert -CAROOT)/rootCA.pem"
```

`--client-ca` triggers `ssl.CERT_REQUIRED` — clients without a valid certificate are rejected
at the TLS handshake, before bearer auth is even checked.

If only `--tls-cert` + `--tls-key` are supplied (no `--client-ca`), the server uses HTTPS
with server-only TLS. Bearer auth still applies.

`--client-ca` without `--tls-cert`/`--tls-key` is an error — K.O.D.A. will refuse to start
with a clear message.

### Flag summary

| Flag | Description |
|------|-------------|
| `--tls-cert PATH` | Server certificate PEM |
| `--tls-key PATH` | Server private key PEM |
| `--client-ca PATH` | CA bundle — enables mTLS (`ssl.CERT_REQUIRED`) |
| `--no-auth` | Disable bearer token (loopback bind only) |
