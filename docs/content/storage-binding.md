# Write a storage binding

The storage binding guide is for a backend author who connects rsauthnz to a store, such as a transactional database
or a store with a single writer. It takes the author from the primitives to a binding that passes the
[conformance suite](conformance.md). It covers:

- The declaration of the guarantees of the binding.
- Each primitive of `rsauthnz::store::Store` and `rsauthnz::store::Journal`, and what it makes atomic or durable.
- The loop that runs the commit driver on the binding.
- The test controls of `rsauthnz_conformance::suite::Subject`, and the four faults of the suite.
- How to read a failed case, with the effects of the commit driver.
- Crash evidence for a binding without crash injection, and disk durability.

Read the guide as the rustdoc of the module `rsauthnz_conformance::guide`. The crate is not published yet, so build
the documentation in the repository:

```sh
cargo doc --locked --no-deps --package rsauthnz-conformance --open
```

The source of the guide is the Markdown file `rsauthnz-conformance/src/guide.md`. Rustdoc checks each of its links
to a public item, and `cargo xtask test` compiles its examples.
