# Security Documentation

Implementation details for the BE-Auth-Service security model.

---

## Purpose

This project was built to study and implement modern authentication and backend security patterns in Java and Spring Boot.

It focuses on:
- secure credential handling
- token lifecycle management
- session control across devices
- defensive API behavior under abuse scenarios

---

## Security Architecture

Request pipeline:
1. CORS policy evaluation
2. Endpoint rate limiting
3. JWT authentication filter
4. Blacklist validation (for access tokens)
5. Controller validation and business logic

Core building blocks:
- `JwtAuthFilter` for token extraction and auth context
- `SecurityConfig` for stateless security rules
- `TokenBlacklistService` for immediate logout invalidation
- `RefreshTokenService` for refresh lifecycle and multi-device control

---

## Authentication Model

### Access Token (JWT)
- Algorithm: RS256
- TTL: 5 minutes (`jwt.access-token.expiration`)
- Claims used: `sub`, `jti`, `iat`, `exp`
- Purpose: authorize protected API requests

### Refresh Token
- TTL: 30 days (`jwt.refresh-token.expiration`)
- Format: cryptographically secure random token
- Stored server-side in PostgreSQL (`refresh_tokens`)
- Bound to device fingerprint metadata
- Supports revocation and "revoke other sessions"

### Email Confirmation Token
- Generated during registration
- TTL in current implementation: 5 minutes
- Stored on `users_authentication.email_confirm_token`

### Password Reset Token
- Generated on forgot-password request
- TTL in current implementation: 15 minutes
- Single-use behavior enforced by nulling token after successful reset

---

## Key Management and JWT Signing

JWT signing uses an RSA key pair managed by `JwtKeyProvider`.

Behavior:
1. Load key pair from configured keystore when available
2. Generate and persist key pair if keystore is missing
3. Fallback to in-memory key pair if keystore operations fail

This allows local development simplicity while supporting persistent signing keys in stable environments.

---

## Password Security

Password hashing is implemented with Argon2id via a custom password encoder.

Why this matters:
- memory-hard design improves resistance to GPU/ASIC cracking
- modern, security-focused hashing strategy
- no plaintext password storage

Applied in:
- registration
- login verification
- password reset updates

---

## Session and Device Security

### Multi-Device Session Handling
Refresh tokens are tracked per user and per device fingerprint.

Current defaults:
- maximum active refresh tokens per user: 5 (`jwt.refresh-token.max-per-user`, default)
- when the limit is reached, the oldest active token is revoked

### Device Fingerprinting Inputs
`RefreshTokenService` derives a stable fingerprint using request metadata, including:
- User-Agent
- Accept-Language
- Accept
- client IP/proxy headers
- additional fetch-context headers when present

Goal:
- avoid duplicate session tokens on same device
- preserve practical session visibility and control

### Session Revocation
Implemented operations:
- revoke current refresh token
- revoke all other user sessions while keeping the current one active

---

## Token Blacklist Strategy

Access-token logout invalidation is handled through a blacklist table:
- table: `token_blacklist`
- primary key: `jti`
- expiry tracking: `expiryDate`

Flow:
1. user logs out with valid access token
2. token `jti` is stored in blacklist until token expiration
3. subsequent requests with same token are rejected

Cleanup:
- scheduled daily cleanup removes expired blacklist entries
- cron in current implementation: `0 0 0 * * *` (midnight)

---

## Abuse Protection: Rate Limiting

Rate limiting is applied at endpoint level.

Configured defaults:
- login: 3 requests / 300s
- register: 2 requests / 600s
- forgot-password: 1 request / 900s
- reset-password confirm: 2 requests / 600s
- refresh-token: 2 requests / 60s
- logout: 5 requests / 300s

Backed by Redis for distributed throttling behavior.

---

## Defensive Security Behaviors

Implemented defensive patterns include:
- email enumeration resistance in forgot-password flow
- stateless authentication (no server HTTP sessions)
- explicit token revocation paths
- centralized error handling for consistent failure responses
- scheduled cleanup tasks to limit stale sensitive artifacts

---

## Security-Critical Data Stores

PostgreSQL persists:
- account credentials and status (`users_authentication`)
- refresh tokens and session metadata (`refresh_tokens`)
- blacklisted access-token JTIs (`token_blacklist`)

Redis stores:
- runtime rate-limiting counters

---

## Scope and Limitations

This repository is a focused authentication/security service for portfolio purposes.

Out of scope in current implementation:
- OAuth2/OpenID Connect providers
- MFA/2FA
- external secret vault integration
- advanced SIEM/audit pipeline integration

These are valid next-step hardening topics if the project evolves beyond portfolio scope.

---

## References

- API docs: [API.md](API.md)
- Rate limiting details: [RATE_LIMITING.md](RATE_LIMITING.md)
- Docker setup: [../docker/DOCKER.md](../docker/DOCKER.md)

---

Last updated: May 19, 2026
