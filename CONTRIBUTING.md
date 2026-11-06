Astraea is general infrastructure for the XRP Ledger, and anyone who runs or uses a history server is welcome to improve it.

# Contributing

We assume you are familiar with the general practice of [making contributions on GitHub](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project). This file covers only what is specific to this project.

Improvements and fixes for ordinary bugs are welcome as pull requests.

Vulnerabilities are different. Send them privately to **dev@xrpl-lending.network**, and do not mention them in an issue, a pull request or a commit message, even when you already have the fix: follow [SECURITY.md](SECURITY.md).

## Before you start

`main` is the only long-lived branch: it holds the latest released or releasable code, and releases are tagged on it.

Every commit on `main` is signed. GitHub must know your verifying key to sign a squashed commit built from your pull request, so please set up [signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification).

External contributions are developed in your own fork. Open a _draft_ pull request soon after pushing your branch, so that others can see the work and comment early.

## Major contributions

For a new method, a change to an existing answer, a new storage format, or a change to the evidence package format, open an issue first and describe what you want to do and why. These choices are hard to undo once servers and clients depend on them.

Astraea answers like Clio 2.8, field for field. A change that makes an answer differ from Clio needs a reason in the pull request and a line in [docs/api.md](docs/api.md). The evidence package format is versioned (`xrpl-witness/evidence/N`, see [docs/evidence-format.md](docs/evidence-format.md)): a change that an older `witness-verify` would read differently needs a new version.

## Before making a pull request

(Or marking a draft pull request as ready.)

Make sure the code builds and passes the same checks CI runs. The compiler version is pinned in `rust-toolchain.toml`.

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

Please write tests for your code. Tests that run offline and finish in seconds belong in `cargo test`. A check against a live node or Clio belongs in `scripts/`, with a note in the pull request on what you ran and what came out.

Rules that the code follows, and that review will ask for:

- No `unsafe`: the workspace forbids it. If something truly needs it, lift the ban for that one module, with a comment saying why.
- No `unwrap` or `expect` outside tests. Astraea parses data it does not control, and a panic there is a denial of service.
- Data from a node or an archive is checked before it is written: the transaction tree against the header, the state tree against the header, the header against validator quorum. Don't add a path that skips this.
- A loop whose length depends on the request checks the request's time limit (`limits::check`).
- Answers that must match xrpld or Clio are compared with them, not only with expectations written by hand.

Changes are usually squashed into a single commit. A larger change can be easier to review as a few logical commits. Either way:

- Present the change as one commit or a logical sequence of commits, not as the history of how it was written.
- Give every commit a [good message](#good-commit-messages).
- Sign every commit.
- Make every commit build and pass the tests, so that `git bisect` keeps working.

### Good commit messages

See ["How to Write a Git Commit Message"](https://cbea.ms/git-commit/). In short: a subject of about 50 characters (72 at most), capitalized, in the imperative mood, without a final period; a blank line; then a body wrapped at 72 characters that explains what changed and why rather than how.

## Pull requests

Pull requests target `main`. While a pull request is a draft, rebase and reorganize it as you like. Once it is marked ready, add changes as new commits and don't force-push, so reviewers can see what changed since their last review. To bring in newer `main`, merge it or use the "Update branch" button.

A pull request needs an approving review from a maintainer and green CI. It is merged with squash-and-merge, which keeps the history of `main` linear.

### Type of change

Start the pull request title with one of these, followed by a colon, a space, and a capitalized summary:

- `feat`: a new feature or method.
- `fix`: a bug fix.
- `perf`: a performance improvement.
- `refactor`: a code change that doesn't change behavior.
- `docs`: documentation only.
- `test`: tests only.
- `build`: the build, dependencies, or the toolchain.
- `ci`: CI configuration.
- `chore`: anything else that doesn't change the binaries.

For example: `feat: Add the validations stream`.

# Maintainers

Maintainers review and merge pull requests and cut releases. Reach them through issues on this repository, or at dev@xrpl-lending.network. Vulnerabilities go only to that address.
