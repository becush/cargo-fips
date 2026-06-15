# Contributing to cargo-fips

Thanks for your interest in contributing! This project follows the conventions
of the Rust and Cargo ecosystem. Please read this guide before opening a pull
request.

By participating, you agree to abide by our [Code of Conduct](./CODE_OF_CONDUCT.md).

## Project ethos: evidence, not absolution

`cargo-fips` surfaces evidence and drift; it never certifies compliance. A green
`check` means "no detected drift from the declared, validated configuration," not
"validated." Keep this distinction intact in code, output, generated summaries,
and docs. Contributions that imply the tool *confers* FIPS compliance will be
asked to reword.

## Ways to contribute

- **Code** — new backend adapters, subcommand work, bug fixes.
- **Registry data** — certificate facts (the project's most valuable asset); see
  [Registry data contributions](#registry-data-contributions).
- **Docs** — the spec (`cargo-fips-spec.md`), this guide, rustdoc.
- **Issues** — bug reports, design discussion. Design is issue-first; cross-cutting
  changes get an RFC-style write-up before code.

## Development environment

Install Rust via [rustup](https://rustup.rs). The pinned toolchain
(`rust-toolchain.toml`) selects stable with `rustfmt` and `clippy`, so no manual
component setup is needed.

```sh
cargo build --workspace
cargo test  --workspace
```

The `cargo-fips-registry` and `cargo-fips-runtime` tests run fully offline. The
`oe` and `guard` subcommands also run offline; `check` shells out to
`cargo metadata` (dependency-graph resolution only — it does not compile the
C-backed crypto crates).

## Before you submit

Every change must pass the following locally:

```sh
cargo fmt --all --check                              # formatting
cargo clippy --workspace --all-targets -- -D warnings # lints, warnings denied
cargo test --workspace                               # unit + integration tests
```

Or run the whole gate in one shot — the three commands above plus the offline
`oe`/`guard` exit-code checks against the fixtures:

```sh
./scripts/preflight.sh
```

CI additionally installs the subcommand and runs it against `fixtures/` to assert
the [exit-code convention](./cargo-fips-spec.md) (0 pass, 1 policy violation,
2 usage error, 3 registry unavailable). If you change behavior, update or add a
fixture.

## Coding standards

- **Formatting is enforced.** Run `cargo fmt`; config lives in `rustfmt.toml`.
- **Clippy must be clean** with `-D warnings`. Prefer fixing lints over `allow`;
  when an `allow` is genuinely warranted, scope it narrowly and add a comment
  explaining why (e.g. forward-looking API consumed in a later phase).
- **Document public items.** Every public item gets a `///` doc comment; every
  module gets a `//!` header. Where a type or function implements part of the
  spec, cite the section (e.g. "spec §10.3"), as the existing code does.
- **Comments explain *why*, not *what*.** Keep them accurate and current; delete
  stale comments rather than letting them rot.
- **Errors, not panics.** Avoid `unwrap()`, `expect()`, and `panic!` outside of
  tests. Use `anyhow` (or typed errors in library crates) and map failures onto
  the exit-code convention.
- **No `unsafe`.** `cargo-fips-runtime` is `#![forbid(unsafe_code)]`; new code
  should stay safe. Any exception needs a written justification in review.
- **Preserve hedged language** in all user-facing strings (see the project ethos).

## Commit conventions

- Keep commits small and focused; each should build and pass tests.
- [Conventional Commits](https://www.conventionalcommits.org) are encouraged,
  with subcommand/area scopes, e.g.:
  - `feat(guard): flag panic=abort for source-built backends`
  - `fix(oe): treat musl as same-OS-family`
  - `docs(spec): clarify vendor-affirmation wording`
  - `data(registry): add wolfCrypt #5041 tested OEs`

## Sign-off and commit signing

This project uses the [Developer Certificate of Origin](./DCO) (DCO). **Every
commit must be signed off**, certifying you have the right to submit it under the
project's license:

```sh
git commit -s        # appends: Signed-off-by: Your Name <you@example.com>
```

Configure your identity once so sign-off matches your authorship:

```sh
git config user.name  "Your Name"
git config user.email "you@example.com"
```

In addition to the DCO sign-off, **cryptographically signed commits are strongly
recommended** (and may be required for merge). Either GPG or SSH signing works:

```sh
# SSH signing (simplest if you already have an SSH key on GitHub)
git config gpg.format ssh
git config user.signingkey ~/.ssh/id_ed25519.pub
git config commit.gpgsign true

# or GPG signing
git config user.signingkey <YOUR_GPG_KEY_ID>
git config commit.gpgsign true
```

Add the public key to your GitHub account so commits show as **Verified**. To do
both at once: `git commit -S -s`.

## Pull request process

1. Fork and branch from `main` (e.g. `feat/guard-rules`).
2. Make your change; keep PRs focused.
3. Ensure `fmt`, `clippy`, and `test` pass, and all commits are signed off.
4. Fill out the PR template (it includes the contributor checklist).
5. Open the PR; link any related issue. CI must be green and at least one
   maintainer review is required before merge.

## Registry data contributions

The certificate registry (`registry/modules/*.json`) is the structured form of
facts otherwise scattered across CMVP Security Policy PDFs, and it is the
project's moat. Vendors (AWS, wolfSSL, Red Hat, …) are explicitly welcome to PR
their own certificate facts.

Requirements for registry changes:

- **Cite provenance.** Every record carries `_sources` (the CMVP certificate URL
  and the Security Policy PDF) and a dated `_note` describing what was verified.
- **Transcribe, don't guess.** Tested operating environments and approved
  algorithms must come from the Security Policy; leave `cavp_certificate` `null`
  until transcribed rather than inventing values.
- **Follow the schema** in `crates/cargo-fips-registry/src/model.rs` and bump
  `schema_version` if the shape changes.
- Add or update a test in `crates/cargo-fips-registry/tests/`.

## Licensing

This project is dual-licensed under [MIT](./LICENSE-MIT) or
[Apache-2.0](./LICENSE-APACHE), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual-licensed as above, without any additional terms or conditions.

## Security

Do not open public issues for security vulnerabilities. Follow the process in
[SECURITY.md](./SECURITY.md).
