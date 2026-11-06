# rsauthnz

Auth for people and for the agents that they own. Passkeys first, post-quantum by default, and no
framework, runtime, or database lock-in.

- **Complete passkeys.** Sign-up, sign-in, more devices, sessions, sign-out, and recovery, with
  ML-DSA offered first. Sign in through Google, Microsoft, Okta, or any OpenID provider with
  FAPI 2.0-grade defaults. An email address never links, recovers, or authorizes an account.
- **Agents with an owner.** Each agent has its own key. A person grants it named actions on named
  resources until a set time, sees each grant, and revokes it at once. Audit records the agent and
  its owner separately.
- **Approval of the exact operation.** A person approves one sensitive agent action with a passkey.
  The approval works once, for that operation only.
- **No races, no lost outcomes.** Each check proposes a change, and your store commits it with its
  audit in one atomic step. A lost reply stays "unknown"; it never becomes a second sign-in. A public
  conformance suite qualifies any backend that you choose.
- **Safe restore.** A restore from an old backup cannot bring back revoked access, and it cannot
  lock a user out.
- **One grant model, every presentation.** TLS-bound native sessions, HTTP message signatures, and
  OAuth 2.1 tokens for MCP servers.
- **Post-quantum credentials.** Composite ML-DSA-65 + Ed25519 on each credential that it issues. All
  cryptography comes from rscrypto. The HTTP layer uses the standard `http` types.

**The bar.** Each release measures against webauthn-rs, jsonwebtoken, and the best OpenID relying
parties. Headline cells must win by a declared margin, and a complete check may cost only a few
percent more than the fastest signature verification alone. Every loss is published, and no
"fastest" claim ships without this evidence.

Status: in development. No release yet.

Part of one family on [rscrypto](https://github.com/loadingalias/rscrypto): rsasync (runtime),
rsnetwork (networking), and rsauthnz (auth). Apache-2.0. Develop with `cargo xtask fix`,
`cargo xtask test`, and `cargo xtask check`.
