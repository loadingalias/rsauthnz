# rsauthnz

**DO NOT USE IN PRODUCTION.**

rsauthnz is authentication and authorization for Rust services: for people, and for the agents
that they own. People sign in with passkeys. A person grants an agent named actions on named
resources until a set time, and can revoke the grant at once. All cryptography comes from rscrypto,
with post-quantum signatures by default. It needs no specific web framework, runtime, or database.

rsauthnz is in development. Each release can change the API.

rsauthnz is one part of a family of Rust libraries:
[rscrypto](https://github.com/loadingalias/rscrypto) (cryptography),
[rsasync](https://github.com/loadingalias/rsasync) (runtime),
[rsnetwork](https://github.com/loadingalias/rsnetwork) (networking),
rsauthnz (auth), and
[rscodec](https://github.com/loadingalias/rscodec) (codecs).

License: Apache-2.0.
