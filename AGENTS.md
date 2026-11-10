# AGENTS.md

Guidance for coding agents working in this repository. [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) are the authority: if this file disagrees with them, follow them and point out the difference.

## What this is

Astraea is a history server for the XRP Ledger. It answers the Clio-compatible JSON-RPC and WebSocket API over the whole public history, and it builds evidence packages that anyone can check offline.

One rule shapes the code: store and serve only what has been checked. Nodes, archives and clients are all untrusted. A node that lies may stall Astraea, but it must not be able to put wrong data into it.

## Layout

The directory and package names differ for one crate. `-p` takes the package name.

| Directory | Package | What it is |
|---|---|---|
| `crates/ledger-engine` | `ledger-engine` | Loader, hot and cold history, indexes, API server. Binaries: `astraea-ingest`, `astraea-snapshot`, `astraea-state`, `astraea-xrpla` |
| `crates/astj5` | `astraea-journal-codec` | ASTJ, the cold-history codec: segment format and block pool |
| `crates/witness-core` | `witness-core` | XRPL primitives: hashing, STObject parsing, keys and signatures, manifests, UNL lists, SHAMap proofs, quorum rules, evidence packages |
| `crates/witness-archiver` | `witness-archiver` | Archives raw signed validations into sealed segments |
| `crates/witness-unl` | `witness-unl` | Polls UNL publishers and keeps every signed list it has seen |
| `crates/witness-store` | `witness-store` | Append-only segment store with a hash chain of seals |
| `crates/witness-verify` | `witness-verify` | Independent checker for the archive and for evidence packages |

Also: `docs/` for the API, architecture, evidence format, metrics and operations; `scripts/` for loading full history and comparing with Clio against live services; `tools/readme-art.py` for the graphics in `assets/`.

Read `docs/architecture.md` before changing how data is loaded, stored or confirmed.

## Commands

The toolchain is pinned in `rust-toolchain.toml` and rustup selects it. `protoc` is not needed, because `build.rs` compiles the protobuf definitions in-process.

These are the CI checks. Run all of them before calling a change finished:

```bash
cargo fmt --all --check
```

```bash
cargo clippy --workspace --all-targets --locked -- -D warnings
```

```bash
cargo test --workspace --locked
```

```bash
cargo deny check
```

`cargo deny` is a separate tool and may need installing. While iterating, test one package:

```bash
cargo test -p ledger-engine --locked
```

Say plainly which of these checks you ran and which you could not run. Do not report a check as passing from reading the code.

## Code rules

- No `unsafe`. The workspace forbids it. If something truly needs it, lift the ban for that one module with a comment saying why.
- No `unwrap` or `expect` outside tests: a panic on data Astraea does not control is a denial of service. `clippy.toml` allows them inside `#[test]` functions. Integration test files in `tests/` declare `#![allow(clippy::unwrap_used, clippy::expect_used)]` at the top.
- CI denies every clippy warning, so `missing_debug_implementations` also fails the build. New public types need `Debug`.
- A loop whose length depends on the request calls `limits::check`, so that the request ends with `tooBusy` instead of holding a slot.
- Every crate inherits the workspace lints with `[lints] workspace = true`. Keep that in any new crate.
- Dependencies come from crates.io only, under the licenses allowed in `deny.toml`. No git dependencies and no wildcard versions. Keep `Cargo.lock` in step, because CI uses `--locked`.
- No crate is published. Leave `publish = false` in place.

## Invariants to preserve

- Data from a node or an archive is checked before it is written: the transaction tree against the header, the state tree against the header, the parent hash chain, and the header against validator quorum. Do not add a path that skips any of this.
- Only ledgers confirmed by quorum are served. A ledger that is loaded but not yet confirmed is not served.
- There is one quorum rule, from the loader to the offline verifier: at least 80% of the full UNL, with the Negative UNL not subtracted. If more than one list could have been in force, quorum must hold for every combination.
- A damaged cold block becomes an error, never a wrong answer.
- New history becomes visible in a fixed order: data files, segment manifests, index files, and the index manifest last. The advertised range must never run ahead of the data.
- UNL lists and validations are archived byte for byte, exactly as they were received.
- `submit` and `simulate` are off by default and never available on a public listener. Astraea never signs on a client's behalf.

## Compatibility

These choices are hard to undo once servers and clients depend on them. For a new method, a change to an existing answer, a new storage format or a change to the evidence package format, an issue comes first.

- **API:** Astraea answers like Clio 2.8, field for field. A difference needs a reason in the pull request and a line in `docs/api.md`. Answers that must match xrpld or Clio are compared with them, not only with expectations written by hand.
- **Evidence format:** it is versioned as `xrpl-witness/evidence/N`. A change that an older `witness-verify` would read differently needs a new version.
- **Cold storage:** older segments stay readable. Keep the readers for older formats when adding a new one.

## Keep in step with the code

| When this changes | Update |
|---|---|
| Behaviour a user or operator can see | `CHANGELOG.md`, under `## Unreleased` (add the heading if it is missing) |
| A method, its answer, an error or a limit | `docs/api.md` |
| A command-line flag or an operating procedure | `docs/running.md` |
| A metric | `docs/metrics.md` |
| The evidence package | `docs/evidence-format.md` |
| Storage or data flow | `docs/architecture.md` |
| Comparison results against Clio | `docs/compared-with-clio.md` |

## Tests

Write tests for your code. Tests that run offline and finish in seconds belong in `cargo test`; saved network data lives in `crates/witness-core/tests/fixtures/`.

A check against a live node or Clio belongs in `scripts/`, not in `cargo test`, with a note in the pull request on what you ran and what came out. These scripts need running services, so do not expect them to work in a plain checkout.

Test only against servers you run yourself. Never point tools at servers run by others.

## Do not edit by hand

- `assets/*.svg`: change `tools/readme-art.py` and regenerate.
- `crates/ledger-engine/proto/`: unmodified definitions from xrpld, under their own license.
- `Cargo.lock`: let cargo update it.

Do not commit local data or build output. `/target`, `/dist`, `/data/`, `*.xwcp` and `.env` files are ignored for that reason. Stage files by name.

## Git and pull requests

- `main` is the only long-lived branch. Pull requests target it and are merged with squash-and-merge. External work happens in a fork.
- Every commit is signed, builds and passes the tests. Present a change as one commit or a logical sequence, not as the history of how it was written.
- Commit subject: about 50 characters (72 at most), capitalized, imperative, no final period. Body wrapped at 72 characters, explaining what changed and why.
- Pull request title: a type, a colon, a space, and a capitalized summary, for example `feat: Add the validations stream`. Types: `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`.
- Fill in the template: "What and why" and "What you ran". Open pull requests as drafts first.
- Once a pull request is marked ready, add new commits and do not force-push. Merge `main` to bring in newer changes.
- Do not bump versions, tag or cut releases unless asked. Maintainers do that.
- Do not commit, push or open a pull request unless asked to.

## Vulnerabilities

Vulnerabilities go only by email to dev@xrpl-lending.network. A public fix shows the problem before servers are patched.

If you find or suspect one, stop and tell the person you are working for. Do not describe it in an issue, a pull request, a commit message, a code comment or a discussion, and do not open a pull request with the fix, not even a draft.

This covers, for example: an evidence package that `witness-verify` accepts although it proves something false; content that differs from what the network validated; a request that crashes the server or uses memory or disk without bound; and a way to reach the node, or methods that must not be forwarded, through Astraea.
