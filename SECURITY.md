# Security

nabd runs on servers, often as root, so its safety matters.

## What nabd promises

- It only reads. It never writes, deletes, restarts or installs anything. The only files it writes are its own
  snapshots (`nabd snapshot`) and the file you name with `-o`.
- It runs only commands that read (see the list in [README.md](README.md#safe-by-design)), with `LC_ALL=C`,
  a time limit and a cap on their output.
- It sends nothing over the network. Only `nabd why dns` sends DNS queries, and it says so.

A case where nabd breaks one of these promises is a security bug.

## Report a vulnerability

Please do not open a public issue. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on <https://github.com/s0sta/nabd/security>.

You get an answer within 7 days. A fix for a confirmed problem is released as soon as it is ready, and you are
credited in the release notes if you wish.

## Supported versions

Only the latest release gets security fixes.

## Verify a release

Every release file is listed in `SHA256SUMS` and has a signed build provenance made by GitHub Actions:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify nabd_linux_amd64.tar.gz --repo s0sta/nabd
```
