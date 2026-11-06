# Security Policy

## Where to send what

| What you have | Where it goes |
|---|---|
| A vulnerability, confirmed or suspected | By email to **dev@xrpl-lending.network**, and nowhere else |
| A bug with no security impact | An issue or a pull request |
| An improvement | A pull request, see [CONTRIBUTING.md](CONTRIBUTING.md) |

If you are not sure whether something is a vulnerability, send it by email.

## Supported Versions

We fix security issues in the latest release and on the `main` branch. Reports about older releases are welcome when the issue is still present in one of those two.

## Identifying and Reporting Vulnerabilities

Please report vulnerabilities privately, by email to **dev@xrpl-lending.network**. Include what you found, how to reproduce it, and what an attacker could do with it. We will confirm we received the report, keep you informed while we work on it, and credit you in the release notes unless you prefer not to be named.

Do not describe a vulnerability in an issue, a pull request, a commit message or a discussion. Do not open a pull request with the fix either, not even a draft: a public fix shows the problem before servers are patched. If you have a fix, attach it to your email. We publish the fix and the details together, in a release.

Issues we especially want to hear about:

- an evidence package (`proof_ledger`, `proof_tx`, `proof_entry`) that `witness-verify` accepts although it proves something false;
- a ledger, transaction or state object served with content different from what the network validated;
- a request that crashes the server, takes it down for other clients, or makes it use memory or disk without bound;
- a way to reach the node behind the server, or methods it must not forward, through Astraea.

### Responsible Investigation

We ask you to investigate carefully and to disclose responsibly. That includes, among other things:

- Testing against a server you run yourself, not against servers run by others. Astraea can load testnet or devnet history as well as mainnet.
- Not attacking physical security, not using social engineering, spam, or denial of service against other people's servers.
- Making a reasonable, good faith effort not to disrupt or harm the operators and users of the XRP Ledger.

## Bug Bounty Program

There is no bug bounty program for Astraea at this time. Issues in xrpld itself, Clio and the XRPL client libraries belong to the [XRPL Foundation's program](https://github.com/XRPLF/rippled/blob/develop/SECURITY.md).

## Running an Astraea server safely

[docs/running.md](docs/running.md) covers deployment: the node it reads from, the limits it applies to requests, and what it leaves to a reverse proxy in front of it. Astraea serves public data, but a server is still something others can overload, and its answers are something clients rely on.
