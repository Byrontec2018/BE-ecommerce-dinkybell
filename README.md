# BE-Auth-Service

Production-ready authentication backend built with Java 21 and Spring Boot 3.
Designed as a portfolio project to demonstrate real-world backend security engineering: identity flows, token lifecycle management, multi-session control, and operational reliability.

![Java](https://img.shields.io/badge/Java-21-orange?logo=java)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.4-green?logo=springboot)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue?logo=postgresql)
![Redis](https://img.shields.io/badge/Redis-6+-red?logo=redis)
![Tests](https://img.shields.io/badge/tests-60%2B-success)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## At a Glance

- Built a complete auth service from scratch in Java/Spring Boot
- Implemented secure registration, login, refresh, logout, and password reset flows
- Applied production-oriented security patterns (RS256 JWT, Argon2id, blacklist, rate limiting)
- Added multi-device session control with token revocation strategies
- Shipped with Dockerized local setup and automated test coverage

---

## Overview

BE-Auth-Service focuses on authentication, session management, and secure token lifecycle handling.
It demonstrates how to design and implement a robust auth layer for Java/Spring applications with production-oriented security choices.

---

## Implemented Concepts

- User registration with email confirmation token
- Login with JWT access token and refresh token
- Refresh token lifecycle management
- Multi-device session management with device fingerprinting
- Session revocation for current device and all other devices
- JWT blacklist for immediate logout invalidation
- Password reset workflow with expiring reset token
- Rate limiting per endpoint with Redis-backed strategy
- Account and auth data persistence in PostgreSQL
- Scheduled cleanup tasks for expired tokens and stale unconfirmed accounts
- Dockerized local environment

---

## Professional Highlights

- End-to-end authentication domain modeled as a dedicated backend service
- Clean architecture with clear responsibility boundaries across controller, service, and repository layers
- Security-first implementation choices aligned with modern backend best practices
- Consistent API response model and defensive error handling across auth workflows
- Feature set validated by 60+ automated tests

---

## Key Security Features

- RS256 JWT signing with asymmetric keys
- Argon2id password hashing
- Short-lived access tokens + long-lived refresh tokens
- Token blacklisting on logout
- Device-aware refresh token reuse/deduplication
- API-level rate limiting protection
- Centralized exception handling and consistent API responses

---

## Architecture

- Layered design: Controller -> Service -> Repository -> Database
- Security pipeline: Request -> JwtAuthFilter -> Token Validation -> Endpoint
- Data stores:
  - PostgreSQL for users, refresh tokens, blacklisted tokens
  - Redis for rate-limiting counters

Authentication flow:
- Register -> Confirmation email token -> Confirm email -> Login
- Login -> Access token + Refresh token -> Protected APIs
- Access token expires -> Refresh endpoint -> New access token
- Logout -> JWT blacklisted -> Immediate invalidation

---

## API Capabilities

Main auth endpoints include:

- `POST /api/v1/auth/register`
- `GET /api/v1/auth/confirm-email`
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/logout`
- `POST /api/v1/auth/refresh-token`
- `POST /api/v1/auth/revoke-token`
- `POST /api/v1/auth/revoke-other-sessions`
- `POST /api/v1/auth/forgot-password`
- `POST /api/v1/auth/reset-password`

For full request/response schemas, see [docs/API.md](docs/API.md).

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Java 21, Spring Boot 3.5.4 |
| Security | Spring Security 6, JWT (RS256), Argon2id |
| Persistence | Spring Data JPA, PostgreSQL |
| Rate Limiting | Redis, Resilience4j |
| Testing | JUnit 5, Mockito |
| Docs | OpenAPI 3 / Swagger UI |
| Build | Maven |

---

## Local Setup

### Prerequisites

- JDK 21
- Maven 3.8+
- PostgreSQL 15+
- Redis 6+
- Docker (recommended)

### Run Locally

```bash
git clone https://github.com/Byrontec2018/be-auth-service.git
cd be-auth-service
source ./setenv.sh
./mvnw spring-boot:run
```

- API base URL: `http://localhost:8080/api/v1`
- Swagger UI: `http://localhost:8080/swagger-ui.html`

### Example Database Bootstrap

```sql
CREATE DATABASE auth_service_db;
CREATE USER admin WITH ENCRYPTED PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE auth_service_db TO admin;
```

---

## Testing

Run all tests:

```bash
./mvnw test
```

Run a specific class:

```bash
./mvnw test -Dtest=UserAuthenticationServiceTest
```

Current suite includes 60+ unit tests covering authentication and token workflows.

---

## Documentation

- [API Reference](docs/API.md)
- [Security Details](docs/SECURITY.md)
- [Rate Limiting Guide](docs/RATE_LIMITING.md)
- [Docker Setup](docker/DOCKER.md)

---

## Portfolio Scope

This repository is intentionally focused on the authentication/security domain.
It is not presented as a full e-commerce backend, but as a specialized auth service showcasing backend security engineering practices.

## Why This Matters

This project demonstrates the ability to:

- Translate security concepts into production-oriented backend code
- Design reliable authentication workflows with practical threat mitigation
- Build maintainable service architecture with strong testing discipline
- Deliver a clear developer experience through documentation and runnable local setup

---

## Author

Stefano D'Inca
Backend Developer

[![GitHub](https://img.shields.io/badge/GitHub-@Byrontec2018-black?logo=github)](https://github.com/Byrontec2018)

---

## License

MIT License - see [LICENSE.txt](LICENSE.txt).
