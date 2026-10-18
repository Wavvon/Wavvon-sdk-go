# Wavvon SDK for Go

> **Community / experimental.** This SDK is maintained in-house only on a
> best-effort basis until an outside maintainer volunteers to own it. It still
> runs the shared conformance suite in CI, so every signed byte it produces is
> checked against the hub's own vectors, but expect its API to change and its
> releases to lag the [TypeScript](https://github.com/Wavvon/Wavvon-sdk-js) and
> [Rust](https://github.com/Wavvon/Wavvon-sdk-rust) SDKs. Want to maintain it?
> Open an issue.

Write programs that talk to a [Wavvon](https://github.com/Wavvon) hub: bots,
apps with slash commands and buttons, event consumers, mini-app hosts, and
receivers for outgoing webhooks.

A program on Wavvon is a client like any other: an Ed25519 keypair, the same
challenge-response login, the same permissions. There is no bot account. What
makes a program an *app* is a role carrying `apps.register`. The design this
module implements is
[sdk.md](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/sdk.md) (tier 1).

- Go 1.23 or later. `context.Context` on every call, errors as values.
- Depends on `github.com/coder/websocket`, `golang.org/x/crypto` (HKDF) and
  `github.com/oapi-codegen/runtime`. Ed25519, HMAC and SHA-256 come from the
  standard library.
- Apache-2.0, so a closed-source program can use it.

## Install

```sh
go get github.com/Wavvon/Wavvon-sdk-go
```

## Quick start

```go
client, err := wavvon.NewClient(wavvon.ClientOptions{
	HubURL:     "https://hub.example",
	Seed:       seed,                        // 32-byte Ed25519 seed. Never sent anywhere.
	InviteCode: os.Getenv("WAVVON_INVITE"), // only needed the first time, on an invite-only hub
})
info, err := client.Info(ctx, false)

go http.ListenAndServe(":8080", &wavvon.DispatchHandler{
	HubPublicKey: *info.PublicKey,
	OnSlashCommand: func(ctx context.Context, inv *wavvon.SlashInvocation) (*wavvon.AppResponse, error) {
		return &wavvon.AppResponse{Reply: &wavvon.Reply{Body: "you said: " + inv.ArgsRaw}}, nil
	},
})

hook := "https://bot.example/hook"
err = client.SetAppProfile(ctx, wavvon.AppProfile{Name: "Echo", WebhookUrl: &hook})
err = client.SetAppCommands(ctx, []wavvon.AppCommand{{Name: "echo", Description: "Repeat after me"}})

events := client.Connect(wavvon.EventStreamOptions{}) // after SetAppProfile
defer events.Close()
for {
	ev, err := events.Next(ctx)
	if err != nil {
		break
	}
	switch e := ev.(type) {
	case *wavvon.MessageEvent:
		fmt.Println(*e.Message.Sender, *e.Message.Content)
	case *wavvon.UnknownEvent:
		fmt.Println("new frame type:", e.RawType)
	}
}
```

A fuller one is [examples/echobot](examples/echobot/main.go).

## What is in it

| Piece | Entry point |
|---|---|
| Login (challenge, sign, verify) that renews itself | `NewClient`, `Client.Login`, `Authenticate`, `IdentityFromSeed` |
| Every REST route, typed from `openapi.yaml` | `client.Rest.<OperationId>WithResponse`, `Check` |
| Retry with backoff on 429, 5xx, timeouts | built into `client.Rest`; `DoWithRetry` |
| Capability checks | `Client.HasCapability`, `Client.RequireCapability` |
| Keyset paging to the end of a list | `Paginate` (an `iter.Seq2`) |
| WebSocket events with resume after reconnect | `Client.Connect` -> `*EventStream`, `Next` |
| HTTP polling instead of a socket | `Client.PollEvents`, `Client.AckEvents` |
| App registration | `SetAppProfile`, `SetAppCommands`, `SetAppSubscriptions` |
| Slash command and button webhooks | `DispatchHandler` (an `http.Handler`), `VerifyDispatch` |
| Outgoing webhook receiver | `VerifyOutgoingWebhook` |
| Mini-app host | `EventStream.AnnounceApp`, `DismissApp`, `SendMiniAppMessage` |

Errors are typed: `*HubError` (a definitive 4xx), `*HubUnavailableError` (the
retry budget ran out; not an answer), `*UnsupportedByHubError` (also matches
`errors.Is(err, wavvon.ErrUnsupportedByHub)`), `*AuthSchemeError`,
`*WebhookVerificationError`. Use `errors.As`.

## Capabilities each feature needs

Hubs say what they support in `GET /info` `capabilities`. The SDK checks those
strings and never compares version numbers. A feature the hub does not
advertise returns `*UnsupportedByHubError`.

| Feature | Capability |
|---|---|
| `SetAppProfile`, `SetAppCommands`, `SetAppSubscriptions`, embeds, game cards | `apps.register` |
| `VerifyDispatch` / `VerifyOutgoingWebhook` (they require `X-Wavvon-Signature-V1`) | `webhooks.signedtimestamp` |
| Paging `GET /users`, `/conversations/{id}/messages`, `/admin/reports` | `list.cursor` |
| Paging bans, mutes, invites, pending, conversations, pins, polls | `list.cursor.lists` |
| `ping` / `pong` over the socket | `ws.ping` |

Login, REST, the socket and polling need no capability.

## Behaviour you can rely on

- **A transient failure is never an answer.** 429, 5xx, timeouts and dropped
  connections are retried with capped exponential backoff and jitter. If the
  budget runs out you get `*HubUnavailableError`, not an empty list or a 404.
  Set `RetryOptions.MaxAttempts` negative to wait until the context ends.
- **Sessions renew themselves.** A 401 triggers one fresh login and a retry.
  `Client.OnStateChange` and `EventStream.OnStateChange` show when it happens.
- **Unknown is delivered.** A socket frame or dispatch type this version does
  not model reaches you as `*UnknownEvent` / `*UnknownDispatch` with the raw
  bytes.
- **Missed events are replayed.** The event stream remembers the last
  `hub_event` seq and asks the hub to resume from it after every reconnect.
  If the gap is older than the hub keeps (72 hours) you get
  `*ReplayUnavailable`. Register the app profile before `Connect`: the hub
  only pushes and replays events on a socket opened by a registered app.
- **Polling is implemented, not relied on.** Today's hub never writes the
  `GET /me/events` queue ([Wavvon-server#170](https://github.com/Wavvon/Wavvon-server/issues/170)); use the socket.
- **The seed stays with you.** No call sends a seed or private key anywhere.

## Conformance

Every signed byte sequence is checked against the shared wire vectors in
Wavvon-server (`crates/identity/wire-vectors.json`): the auth challenge, the
Ed25519 dispatch signature, and the outgoing-webhook HKDF + HMAC. CI reads
them from Wavvon-server at commit `eb11d75657ee8362dd42a7982fc5b13a3dcc4e68`.

The REST client was generated from Wavvon-docs at the commit in
[rest/SPEC_COMMIT](rest/SPEC_COMMIT).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
