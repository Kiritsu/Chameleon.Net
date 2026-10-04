# Contributing to Chameleon.Net

Thanks for helping. Bug reports, new profiles, fixes and features are all welcome. This page covers how to get set up
and what a pull request needs to be merged.

## Reporting bugs and requesting features

Open an issue with the [bug report](https://github.com/Kiritsu/Chameleon.Net/issues/new?template=bug_report.yml) or
[feature request](https://github.com/Kiritsu/Chameleon.Net/issues/new?template=feature_request.yml) form.

- For a fingerprint that doesn't match the real client, include both sides: JA3/JA4, the Akamai HTTP/2 string or the
  header list from Chameleon.Net and from the real client, as seen by the same service (the
  [Inspector](README.md#inspector) or tls.peet.ws).
- Remove cookies, tokens, credentials and other secrets from code, logs and captures before posting them.
- Don't report security vulnerabilities in a public issue. Use
  [private vulnerability reporting](https://github.com/Kiritsu/Chameleon.Net/security/advisories/new) instead.

New browser versions on Windows, macOS and Linux are captured every week by the
[Profiles workflow](README.md#automated-profile-updates), so there's no need to open an issue or a pull request for them.

## Getting started

You need the .NET SDK pinned in [global.json](global.json) (10.0.3xx or a later feature band). Then:

```bash
dotnet build Chameleon.Net.slnx
dotnet test --solution Chameleon.Net.slnx
```

The repository holds:

| Path | What it is |
|---|---|
| `src/Chameleon.Net` | The library: transport, TLS, HTTP/1.1, HTTP/2, WebSockets and the profiles |
| `src/Chameleon.Net.Extensions.Http` | `IHttpClientFactory` and dependency injection integration |
| `tools/Chameleon.Net.Inspector` | The local fingerprinting server, also used by the tests |
| `tests/Chameleon.Net.Tests` | xUnit v3 tests |
| `eng/profile-capture` | Scripts for the automated profile captures |
| `docs` | Longer guides, such as [creating a profile](docs/creating-a-profile.md) |

## Tests

The default test run is offline and is what CI runs on Linux and Windows for every pull request. It has to pass.

Tests that talk to real servers (tls.peet.ws, Cloudflare, Google, ...) are marked `[Fact(Explicit = true)]` and are
skipped by default. Run them with:

```bash
dotnet test --solution Chameleon.Net.slnx -- --explicit only
```

Live tests are a spot check and are never required for a pull request. Anything that must keep working belongs in an
offline test: replay a capture, or run against the Inspector or Kestrel over loopback, as the existing tests do.

Every behavior change or bug fix should come with a test that fails without it.

## Code style

- Warnings are errors (`TreatWarningsAsErrors`, `AnalysisLevel` `latest-recommended`, nullable reference types on), so
  the build stays clean.
- Follow the style of the surrounding code: naming, layout, and comment density.
- Package versions live in [Directory.Packages.props](Directory.Packages.props) (central package management). Add a
  `PackageVersion` there and a `PackageReference` without a version in the project. Keep new dependencies of the library
  to a minimum.
- Public API is part of the packages' contract. Discuss breaking changes in an issue first.
- Don't change version numbers: versions come from git tags (see [Versioning and releases](README.md#versioning-and-releases)).

## Profiles

A profile is plain data, so its value is only as good as its capture. [docs/creating-a-profile.md](docs/creating-a-profile.md)
covers capturing a client, turning the capture into a profile and verifying it. A new built-in profile needs:

- One file in `src/Chameleon.Net/Profiles/BuiltIn/<Name>.cs`, with the expected JA3/JA4/Akamai strings and the capture
  provenance (client build, OS, date, method) in its `<summary>`.
- A golden test in `tests/Chameleon.Net.Tests/Profiles/` that checks those fingerprints offline.
- A capture from the real client, not hand-edited from another profile. The Inspector's `/capture` page exports one.

A versioned profile name such as `Edge153Windows` never changes once released. Fixes to a released profile should say
in the pull request what was wrong and how it was checked against the real client.

## Pull requests

- Keep each pull request to one change, and open an issue first for anything large.
- Describe what changed and why. For fingerprint changes, include the before and after fingerprints.
- Make sure the build and the offline tests pass locally.
- Update the README or the docs when behavior or usage changes.

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
