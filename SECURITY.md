# Security policy

**English** · [Norsk](SECURITY.no.md)

## Reporting a vulnerability

If you find a security vulnerability in kauth, please don't open a public GitHub issue. Send a private report through GitHub Security Advisories (the Security tab on the repository) or directly to `lsoraas@gmail.com`.

Include as much detail as you can: which version, what you did, what you expected, what actually happened, and a possible impact. A proof of concept or a sample attack is useful — but send it privately, not in a public forum.

We aim to acknowledge receipt within 72 hours. Actual response and fix time depends on severity and complexity, but rest assured we treat these with priority.

## Supported versions

kauth has no formal releases yet. `master` is the only supported branch, and fixes land there. If you're running an older commit, move to a recent `master` for security updates.

Every push to `master` and every pull request runs CI on GitHub Actions: gofmt, `go vet`, tests, tests with `-race`, `govulncheck` and an end-to-end test of the sign-in flow. Pushes to `master` (and manual runs) also run short fuzz tests of the security boundaries (redirect_uri matching, state parsing, `/dispatch` targets, log masking). The toolchain is Go 1.26.9 (`toolchain go1.26.9` in `go.mod`); Go 1.25 is no longer supported upstream and had 32 reachable standard-library vulnerabilities.

## In scope

- Authentication and authorisation flows (OIDC, magic link, password, refresh-token rotation)
- Token issuance and verification (JWT, JWKS)
- Cookie handling (HttpOnly, Secure, SameSite)
- HMAC state and state-cookie handling for OIDC
- Anti-enumeration and rate-limiting mechanisms
- Admin panel: authentication, authorisation, CSRF surfaces
- Cross-host login flow (URL token passing, redirect_uri cookie)
- File upload in the admin panel (background images)
- SQL handling (even though we use sqlc and parameterised queries)
- CSV export (formula-injection handling)

## Out of scope

- Vulnerabilities in Cloudflare, modernc.org/sqlite, golang-jwt or other third-party dependencies — report those upstream.
- Social-engineering attacks against administrator users.
- Physical access to the server.
- DoS through resource exhaustion (we have basic limits; extreme cases are handled upstream by Cloudflare).

## Threat model in brief

kauth is designed for self-hosted environments serving a handful of services. The assumptions are:

- It runs behind an HTTPS-terminating reverse proxy (Cloudflare Tunnel in our case)
- The client IP arrives in the `CF-Connecting-IP` header
- Admin accounts (users with the `konge` role) are created manually and trusted
- The RSA private key is secret and hosted alongside the binary
- Resource servers validate JWTs against JWKS

If those assumptions break — kauth exposed directly on a public network without TLS, say, or several unsanctioned accounts holding the `konge` role — the security model no longer holds.

## Design decisions that are security-relevant

- Passwords disabled by default — see the [README](README.md) for the reasoning.
- Refresh-token rotation with family revocation on reuse (OAuth BCP §4.13).
- Constant-time HMAC comparison on state cookies.
- Anti-enumeration on magic link and admin login (200 ms floor plus identical responses).
- Rate limiting on magic links (3 attempts per 15 minutes per email address).
- Generic OIDC providers (`identity_providers`) are loaded only when the issuer is in both the table and the `KAUTH_OIDC_ISSUERS` allowlist, so a database write alone cannot add a trusted issuer. All outbound traffic to them goes through one client: https only, no redirects, size and time limits, and a dial guard against non-public addresses. Their email is untrusted by default (`trust_email=0`: only already-linked identities sign in); with `trust_email=1` it needs `email_verified`, a plain-ASCII address and a domain on the provider's list. Client secrets live in `KAUTH_IDP_*` environment variables, never in the database, and a generic identity never grants admin access. Operations guide: [doc/IDENTITY_PROVIDERS.md](doc/IDENTITY_PROVIDERS.md).
- GitHub sign-in (`/github-login`, `/github-callback`) uses fixed hosts in code, the same locked outbound client as generic OIDC, PKCE and a state with its own purpose (`:github`) that no other callback accepts, and vice versa. The identity is the numeric GitHub id, never the username. Only the primary, verified, plain-ASCII, non-`noreply` address is used for linking or registration; otherwise only an already-linked identity can sign in. GitHub never grants admin access (enforced by a `CHECK` on `user_identities`). The client secret lives in a `KAUTH_SVC_*` or `KAUTH_GITHUB_CLIENT_SECRET` environment variable, and the GitHub token is never stored or logged. GitHub, Inc. is a sub-processor for services that enable it.
- Audit writes isolated in a goroutine — an audit failure can never block authentication.
- Explicit `Secure: true` on every cookie (overridable for local HTTP development through `KAUTH_INSECURE_COOKIES=true`).
- CORS disabled by default (`KAUTH_CORS_ORIGINS=` empty list means no CORS headers at all). Enabled only for specific endpoints (`/token`, `/.well-known/*`).

## Known limitations

- `KAUTH_GITHUB_BASE_URL` and `KAUTH_GITHUB_API_URL` are accepted only together with `KAUTH_OIDC_ALLOW_INSECURE=true` (evaluation only, never production).
- The federated callbacks (`/callback`, `/ms-callback`, `/github-callback`, `/idp/{slug}/callback`) are unauthenticated public endpoints with no rate limit of their own beyond the signed, short-lived state.
- `KAUTH_OIDC_ALLOW_INSECURE=true` (http and loopback towards OIDC providers) exists for local development and evaluation only. It must never be set in production. kauth refuses to start with it unless `KAUTH_INSECURE_COOKIES=true` is also set.
- We haven't run a formal penetration test. The code has been reviewed internally, but no external review has been carried out.
- The magic-link rate limiter is process-local (in-memory). If kauth runs as several instances behind a load balancer, each instance keeps its own tally. kauth currently runs as a single instance, so this isn't a problem in practice.
- No automated rotation of the RSA signing key. Changing it manually requires a coordinated deploy.
