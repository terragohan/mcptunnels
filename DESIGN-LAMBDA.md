# tunneld on API Gateway + Lambda + D1 — design spec

Status: draft for approval. No code has been written for this port.
Target: AWS account `951928130124` (MCP Tunnels), region `us-east-2`, Terraform in
`infra/mcptunnels-lambda/` (new dir; the healthy Fargate stack in `infra/mcptunnels/`
stays untouched as fallback until DNS cutover).

## 0. The one finding that shapes everything

Today the tunnel is a **yamux session** running over a single WebSocket between agent
and tunneld (`internal/gateway/gateway.go`, `internal/agent/agent.go`). yamux is a
stateful in-memory machine: per-stream flow-control windows, SYN/ACK/FIN bookkeeping,
30s keepalive pings, 10s write timeouts. Public requests stream through it — MCP SSE
responses are deliberately **uncapped and unbounded** (`internal/proxy/proxy.go:93-96`).

Lambda cannot hold a yamux session:

- API Gateway delivers each inbound WS message as a **separate `$default` invocation**;
  server→agent bytes can only leave via `apigatewaymanagementapi PostToConnection`.
- There is no way to keep a `*yamux.Session` (or an open stream per HTTP request) alive
  across invocations. Serializing yamux state into D1 between messages means
  reimplementing yamux as a distributed state machine, and the per-message D1 +
  management-API round trips would blow yamux's 10s `ConnectionWriteTimeout`.

Therefore this port is a **wire-protocol redesign**, not a lift-and-shift:

1. The tunnel protocol becomes a stateless request/response envelope over WS binary
   messages, correlated by request ID, with pending state in D1.
2. **The agent (`internal/agent`, `cmd/mcptunnel`) must change.** The deployed agent
   speaks yamux; a new agent build is required before cutover.
3. **Unbounded SSE streaming is lost.** API Gateway REST/HTTP APIs cap Lambda
   responses at ~6 MB and 29s. Long-lived SSE breaks at 29s; MCP streamable-HTTP
   clients that support resumption (`Last-Event-ID`) recover, others fail. Responses
   over 6 MB fail. This is the capability regression to accept consciously.

Everything outside the transport triple (gateway/proxy/agent) ports almost verbatim:
control plane, OAuth server, store (D1 backend already exists), janitor.

## 1. New wire protocol (replaces yamux)

Envelope: JSON control wrapper with base64 payloads, sent as WS binary messages.

- `Request {id, method, path, headers, body_b64}` — server → agent, via
  `PostToConnection`.
- `ResponseChunk {id, seq, status?, headers?, body_b64, final}` — agent → server, over
  the tunnel WS, received by the `$default` Lambda and written to D1.
- `Ping {}` / `Pong {}` — agent sends a ping every ~5 min to stay under API Gateway's
  10-minute idle timeout (replaces yamux keepalive).

Flow for one public HTTP request:

1. `http-proxy` Lambda authenticates, generates `request_id`, looks up the agent's
   `connection_id` in D1, writes a `pending_requests` row, then `PostToConnection`s
   the `Request`.
2. Agent executes against its upstream (existing `handleStream` logic, minus yamux),
   sends one or more `ResponseChunk`s back over the tunnel WS.
3. `ws-message` (`$default`) Lambda writes chunks to a `response_chunks` D1 table
   keyed by `(request_id, seq)`.
4. `http-proxy` polls D1 (~200ms interval, deadline ~25s) until `final`, assembles,
   returns the response.

Known costs of this design:

- `http-proxy` Lambda is billed for the **full duration of every request** while it
  polls (previous idle-cost estimate understated this). Still cheap at low volume.
- ~300–600ms added latency per request (PostToConnection + D1 polling).
- API Gateway WS connection max lifetime is 2 hours → agent reconnect loop already
  exists (`internal/agent/agent.go:77-93`) and handles this unchanged.
- Message payload cap 128 KiB → chunk bodies at e.g. 96 KiB.

## 2. D1 schema additions

New tables (new migration alongside existing schema):

- `connections(tenant, service, connection_id, connected_at)` — written by
  `ws-connect`, deleted by `ws-disconnect` (only if connection_id matches, preserving
  reconnect-takeover semantics from `gateway.go:128-134`), read by `http-proxy`.
- `pending_requests(request_id PK, tenant, service, connection_id, created_at)` —
  enables janitor cleanup and debugging.
- `response_chunks(request_id, seq, status, headers_json, body BLOB, final,
  created_at)` — written by `ws-message`, polled by `http-proxy`, deleted on
  completion.

`store.API` gains ~4 methods (UpsertConnection, DeleteConnection, GetConnection,
PutChunk/GetChunks/DeleteRequest). Both sqlite and D1 implementations (sqlite keeps
the standalone binary working).

## 3. Lambda functions

| Lambda | Trigger | Reuses (near-verbatim) |
|---|---|---|
| `ws-authorizer` | `$connect` Lambda authorizer | header auth from `gateway.ServeHTTP` (`gateway.go:48-59`), `ValidateAgentKey` |
| `ws-connect` | `$connect` | `gateway.register` semantics |
| `ws-disconnect` | `$disconnect` | `gateway.unregister` semantics |
| `ws-message` | `$default` | new: envelope parse, chunk write |
| `http-proxy` | HTTP API `/t/{tenant}/s/{service}/*` | `proxy.splitPath`, 8 MiB body cap, `GetService`, local JWT verify |
| `control-plane` | HTTP API `POST/DELETE /api/v1/quick` | `internal/controlplane` as-is |
| `oauth` | HTTP API `/t/{tenant}/{authorize,token,register,jwks.json}` + `/.well-known/*` | `internal/oauth` as-is |
| `janitor` | EventBridge 1/min | `DeleteExpiredTenants` + chunk/pending cleanup |

Per-invocation state that today is cached in memory:

- `oauth.Resolver.servers` cache → rebuilt per invocation (one `GetTenant` +
  `GetSigningKey`; cheap).
- In-memory rate limiters (`tokenRate`, `registerRate`, `oauth.go`) → D1 counters in
  the style of `QuickRateHit`, or accept cold-start resets (document choice).

Removed entirely: `cfg.tls.*` / ACME autocert block in `cmd/tunneld/main.go` (TLS
terminates at API Gateway custom domain with an ACM cert). `listen`, `database_path`
irrelevant in Lambda; config becomes env vars.

## 4. Agent changes (`internal/agent`, `cmd/mcptunnel`)

- Replace `yamux.Server` accept loop with an envelope read loop.
- `handleStream` logic (upstream rewrite, header strip/inject, no-timeout client)
  carries over; response is chunked into `ResponseChunk`s instead of `resp.Write`.
- Add ping ticker (~5 min) and envelope-aware reconnect.
- Version gate: agent and server must agree on protocol — bump tunnelproto version and
  fail loudly on mismatch.

## 5. AWS infrastructure (`infra/mcptunnels-lambda/`)

- WebSocket API Gateway (`$connect`/`$disconnect`/`$default`) + Lambda authorizer.
- HTTP API Gateway for proxy/control-plane/OAuth routes.
- ACM cert (us-east-2; API Gateway custom domains are regional) + custom domain for
  `t-mcptunnels.terragohan.com` — DNS validation record stays manual in Cloudflare,
  same as the current cutover plan.
- Lambdas: Go (provided.al2023) or container from the existing build; env vars carry
  `D1_ACCOUNT_ID`, `D1_DATABASE_ID`, `D1_API_TOKEN`, `PUBLIC_BASE_URL`.
- EventBridge schedule → janitor.
- Account guard: `aws_account_id = "951928130124"` pinned + `EXPECTED_AWS_ACCOUNT` in
  deploy script, matching existing convention. State: existing bucket
  `terragohan-tfstate-951928130124`, key `mcptunnels-lambda/terraform.tfstate`.

## 6. Sequencing

1. Spec approval (this document).
2. `store.API` extension + sqlite + D1 implementations + migrations; unit tests
   (fake-D1 pattern from `stored1/store_test.go`).
3. Protocol package (`internal/tunnelproto` v2 envelopes) + agent rewrite; agent
   integration test against a local fake WS server.
4. Lambda handlers; unit tests with fake management-API client + fake D1.
5. Terraform stack; deploy to `951928130124` with `AWS_PROFILE=terragohan-mcp`.
6. Live acceptance against real D1: quick create → agent connect (new build) → public
   proxy round trip → OAuth discovery → delete.
7. DNS cutover decision (Fargate stack remains the fallback until then).

## 7. Honest effort estimate

Steps 2–4 are the bulk: a protocol redesign touching server, agent, and store, plus a
new AWS stack. This is substantially larger than the D1 backend work already done.
The alternative that keeps today's protocol intact is the already-deployed Fargate
stack (~$26/mo) or an EC2 t4g.micro (~$8/mo) middle ground — both keep unbounded SSE
and require no agent change.
