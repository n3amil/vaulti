# Security

Vaulti is an early, **unaudited** project. Don't store real secrets in it yet.

## Reporting a vulnerability

Please report security issues privately via
[GitHub private vulnerability reporting](https://github.com/n3amil/vaulti/security/advisories/new),
not in public issues. Include steps to reproduce and the version/commit.

## Scope

In scope: the vault format and crypto (`core/`), sync/pairing protocol (`sync/`),
the desktop/Android app (`app/`), and the build/release pipeline (`.github/`).

## Release integrity

Release artifacts are built only by GitHub Actions from version tags, which only
the maintainer can create. Third-party actions are pinned to commit SHAs.
