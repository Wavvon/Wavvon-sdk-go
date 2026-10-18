# Contributing

This SDK is community / experimental and looking for an outside maintainer.
If that could be you, open an issue.

1. Branch from `develop` and open the pull request against `develop`.
2. `scripts/check` must pass. If you touched auth, the socket or webhooks,
   also run the smoke test against a real hub (`go run ./cmd/smoke`, see
   CLAUDE.md).
3. Do not edit `rest/` by hand. Run `scripts/generate.sh <Wavvon-docs
   checkout> [git-ref]` and commit the result with the new `SPEC_COMMIT`.
4. A new signed byte sequence starts as a change in
   [Wavvon-server](https://github.com/Wavvon/Wavvon-server) with a wire
   vector, never here.
5. A feature that needs a hub capability checks it with `RequireCapability`
   and lists it in the README table.

Contributions are licensed under Apache-2.0 (see LICENSE).
