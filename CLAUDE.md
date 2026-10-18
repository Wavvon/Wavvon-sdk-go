# CLAUDE.md

Guidance for working in this repo: `github.com/Wavvon/Wavvon-sdk-go`, the Go
SDK for programs (bots and apps) that talk to a Wavvon hub. It ships as
**community / experimental** (best-effort in-house maintenance). The design is
[sdk.md](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/sdk.md); this is
its tier 1. Hub code lives in
[Wavvon-server](https://github.com/Wavvon/Wavvon-server), the REST spec and
protocol docs in [Wavvon-docs](https://github.com/Wavvon/Wavvon-docs). The
[TypeScript SDK](https://github.com/Wavvon/Wavvon-sdk-js) is the reference
this one mirrors.

## Commands

```sh
scripts/check                 # gofmt -l, go vet, staticcheck, go test. Must pass before a commit.
go test ./...
scripts/generate.sh [docs-path] [git-ref]   # regenerate rest/ (default ../../docs at HEAD)
go run ./cmd/smoke            # real hub binary, see below
```

`go.mod` targets Go 1.23: keep dependencies at versions whose own `go`
directive is 1.23 or lower (`go mod tidy` will otherwise raise it), and use
`golang.org/x/crypto/hkdf`, not `crypto/hkdf` (1.24+).

Code comments in English, only where the why is not obvious. Doc comments on
every exported identifier. No comments in GitHub Actions workflow files:
explain choices in the commit message.

## Layers

1. **Generated REST** - `rest/rest.gen.go`, from Wavvon-docs `openapi.yaml` by
   `scripts/generate.sh` (oapi-codegen, pinned in the script; config
   `rest/oapi-codegen.yaml`). Committed. The spec is read from a git commit,
   never the working tree, and passed through `scripts/specpatch` (its own
   module) which fixes only what oapi-codegen rejects and prints each fix;
   `rest/SPEC_COMMIT` gets `+specpatch` when it did. Each printed fix is a
   spec bug for Wavvon-docs. Never edit the generated file by hand.
2. **Hand-written core** - package `wavvon` at the root: `auth.go` challenge
   rules and login; `retry.go` backoff (`DoWithRetry`); `client.go` `Client`
   (the generated client's transport adds the bearer, retries and
   re-authenticates on 401), capabilities, app registration, polling, `Check`;
   `pager.go`; `events.go` the WebSocket stream and frame types; `webhooks.go`
   dispatch and outgoing-webhook verification, reply types, `DispatchHandler`.
3. **Conformance** - `conformance_test.go` reads Wavvon-server
   `crates/identity/wire-vectors.json` (default `../../server/...`, or
   `WAVVON_WIRE_VECTORS`). Strings starting with `@` refer to `fixtures`. It
   is never copied into this repo. Missing file: loud skip locally (shown by
   `scripts/check`), failure when `CI` is set.

## Rules the SDK must keep (sdk.md §5, §6)

- **Capabilities, never versions.** Gate features on `GET /info`
  `capabilities` and return `*UnsupportedByHubError`. Never compare `version`.
- **429 is "not now", never "no".** Retry 429/5xx/timeouts/network errors with
  capped exponential backoff and jitter. On exhaustion return
  `*HubUnavailableError`; never turn a transient failure into an empty list,
  "not found", or any other definitive answer. A pager page that fails is
  yielded as an error, never the end of the list.
- **Unknown is loud.** Unknown socket frames and dispatch types are delivered
  as `*UnknownEvent` / `*UnknownDispatch` with the raw bytes, never dropped.
  A known type whose fields do not decode is delivered as unknown too.
- **Re-auth on its own**, with the state observable (`OnStateChange`).
- **Auth challenge**: the challenge is hex. `scheme: "tagged-v1"` -> sign
  `"wavvon/auth-challenge/v1\0" || challenge`; no scheme -> raw only at
  exactly 32 bytes; any other scheme (including "") -> `*AuthSchemeError`,
  not retried.
- **Never send the seed** or any private key anywhere. Never invent a wire
  format: signed bytes come from wire-format.md and the vectors; a new one is
  a server-side change first. Never model a bot as an account or send
  `is_bot`. Tier 1 is community-axis only (no DMs E2E, pairing, home hub).

Code is authoritative over docs. When they disagree, follow the hub code and
report the doc bug to Wavvon-docs.

## Facts verified against the hub that the docs get wrong or omit

- The hub drops a pending challenge as soon as verify reads it, so a transient
  verify failure restarts from a fresh challenge.
- `resume` and `hub_event` push only work on a socket whose identity had an
  app profile **when it connected**. Register first, then `Connect`.
- Replay can re-deliver: live events that arrive during a replay are flushed
  after it. The stream drops any `hub_event` with seq <= the last seen.
- The app side of a mini-app sends `app_announce` / `app_dismiss` and talks to
  players with `mini_app_message` + `to_pubkey`; players arrive with
  `from_pubkey`. `app_join` is answered by the hub, not the app.
- Paging: a bare array plus `limit` (default 100, max 500) and `cursor` = key
  of the previous page's last row; the key differs per endpoint (`code`,
  `public_key`, `id`), hence `Paginate`'s key func. A hub without the
  capability ignores the cursor: `Paginate` returns `ErrCursorIgnored`.
- Outgoing-webhook secret as shown is base64url without padding; HKDF input
  is the **decoded** bytes; the HMAC key is the 32 HKDF bytes, not hex.
- The hub never writes `GET /me/events` today (Wavvon-server#170).
- A fresh hub has no channel; the smoke creates one.

## Smoke test

`cmd/smoke` runs against a real hub. With `WAVVON_SMOKE_HUB` and
`WAVVON_SMOKE_INVITE` (an invite whose role grants `apps.register`) it uses
that hub. Without them it copies a hub binary (`WAVVON_HUB_BIN`, default a
sibling Wavvon-server checkout's `target/debug/wavvon-hub`) to a temp dir,
boots it on a fresh database `wavvon_sdk_go_smoke` in a PostgreSQL docker
container (`WAVVON_PG_CONTAINER`, default `wavvon-pg`), sets up a role, invite
and channel as owner, runs the smoke, kills only the process it started and
drops the database. In-process tests have missed every cross-process bug this
project has had: run it when touching auth, the socket or webhooks.

## Git

Work on `develop`; `main` is for releases. Commit in logical steps.
