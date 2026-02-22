# 🛍️ Dinkybell E-Commerce Backend

> Production-grade REST API for an e-commerce platform built with **Java 21** and **Spring Boot 3**, focused on secure authentication, session management, and scalable backend architecture.

![Java](https://img.shields.io/badge/Java-21-orange?logo=java)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.4-green?logo=springboot)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-blue?logo=postgresql)
![Redis](https://img.shields.io/badge/Redis-6+-red?logo=redis)
![Tests](https://img.shields.io/badge/tests-60%2B-success)
![Coverage](https://img.shields.io/badge/coverage-High-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Architecture](https://img.shields.io/badge/architecture-layered-blueviolet)
![Security](https://img.shields.io/badge/security-production--grade-success)
![API](https://img.shields.io/badge/API-REST-informational)

---

## 📋 Overview

Dinkybell is a backend system designed for modern e-commerce applications.
It demonstrates production-level backend architecture, secure authentication patterns, and scalable API design.

**The project showcases:**
- Secure authentication design (JWT with asymmetric encryption)
- Multi-device session management with device fingerprinting
- Token lifecycle management (generation, validation, rotation, blacklisting)
- Distributed rate limiting with Redis
- Clean layered architecture
- Comprehensive automated testing

---

## ✨ Core Features

- **JWT Authentication** - RS256 asymmetric signing with 2048-bit RSA keys
- **Refresh Token System** - Multi-device session management (max 5 devices)
- **Device Fingerprinting** - Unique device tracking to prevent token duplication
- **Token Blacklisting** - Immediate logout invalidation
- **Email Verification** - Confirmation tokens for account activation
- **Password Reset** - Secure email-based recovery workflow
- **Redis Rate Limiting** - Custom aspect-oriented per-endpoint throttling
- **Argon2id Hashing** - OWASP-recommended password security
- **Global Exception Handling** - Unified API error responses
- **OpenAPI Documentation** - Interactive Swagger UI
- **Comprehensive Testing** - 60+ unit tests with 100% pass rate

---

## 🏆 Skills Demonstrated

This project highlights a wide range of backend development and software engineering skills:

- **Java & Spring Boot** – Clean architecture, layered design, dependency injection, and modular service implementation  
- **RESTful API Design** – Secure endpoints, proper status codes, and standardized JSON responses  
- **Authentication & Security** – JWT-based authentication, refresh token rotation, device fingerprinting, password hashing with Argon2id, email verification workflow  
- **Database Management** – PostgreSQL design, schema modeling, indexing, transactions, and integration with Spring Data JPA  
- **Caching & Rate Limiting** – Redis usage for performance optimization and per-endpoint throttling  
- **Testing & Quality Assurance** – Unit testing with JUnit and Mockito, test coverage validation, automated workflow testing  
- **DevOps Awareness** – Dockerized setup, environment variable management, Maven build automation, deployment readiness  
- **API Documentation** – OpenAPI / Swagger integration for clear developer communication  
- **Problem Solving & System Design** – Multi-device session handling, secure token lifecycle management, error handling, and concurrency control  
- **Version Control & Collaboration** – Git usage for branches, commits, and repository organization  

Demonstrates the ability to deliver a production-ready backend system with emphasis on security, scalability, and maintainable code.

---

## 🏗️ Architecture

- **Layered Architecture:**  Controller → Service → Repository → Database    
- **Security Layer:** Request → JwtAuthFilter → Token Validation → Controller  
- **Infrastructure:**  
Spring Boot Application  
├── PostgreSQL (Primary Data Store)    
└── Redis (Rate Limiting & Caching)  
- **Authentication Flow:**
  Login → Validate Credentials → Generate JWT + Refresh Token → Device Fingerprint → Store Session → Return Tokens  
- **Multi-Device Sessions:**  
  - Maximum 5 concurrent sessions per user
  - Device fingerprinting prevents token duplication
  - Automatic rotation when limit exceeded (oldest revoked)

---

## 🛠️ Tech Stack

| Layer             | Technology                               |
|-------------------|------------------------------------------|
| **Backend**       | Java 21, Spring Boot 3.5.4               |
| **Security**      | Spring Security 6, JWT (RS256), Argon2id |
| **Database**      | PostgreSQL 15+                           |
| **Caching**       | Redis 6.0+                               |
| **Testing**       | JUnit 5, Mockito                         |
| **Documentation** | OpenAPI 3.0 / Swagger UI                 |
| **Build**         | Maven 3.8+                               |

---

## Security Highlights

- Argon2 password hashing
- short-lived access tokens
- refresh token rotation
- session concurrency control
- rate limiting protection
- secure token generation
- environment-based secrets

---

## Environment Configuration

Required environment variables:

```bash
export DB_HOST="<db_host>"
export DB_PORT="<db_port>"
export DB_NAME="<db_name>"
export DB_USER="<db_user>"
export DB_PASSWORD="<db_password>"

export REDIS_HOST="<redis_host>"
export REDIS_PORT="<redis_port>"
export REDIS_PASSWORD="<redis_password>"

export PGADMIN_EMAIL="<pgadmin_email>"
export PGADMIN_PASSWORD="<pgadmin_password>"

export EMAIL_HOST="<email_host>"
export EMAIL_PORT="<email_port>"
export EMAIL_USERNAME="<email_username>"
export EMAIL_PASSWORD="<email_password>"
```

Use [.env.example](.env.example) as a safe template for local setup.

---

## 🚀 Quick Start

### Prerequisites

Before setting up the project, ensure you have the following installed:

#### Required
- Java Development Kit 21 (JDK 21)
- Maven 3.8+
- PostgreSQL 15+
- Git

#### Optional but recommended
- Redis Server 6.0+ (for rate limiting)
- Docker (for database containerisation)
- Postman or similar API client for testing

### Installation
```bash
git clone https://github.com/Byrontec2018/BE-ecommerce-dinkybell.git
cd BE-ecommerce-dinkybell
source ./setenv.sh  # Configure environment variables
./mvnw spring-boot:run
```

**API Available at:** http://localhost:8080  
**Swagger UI:** http://localhost:8080/swagger-ui.html

### Database Setupsql
CREATE DATABASE ecommerce_db;
CREATE USER admin WITH ENCRYPTED PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE ecommerce_db TO admin;`

### Authentication Flow Example

- Register user
- Confirm email
- Login → receive JWT + refresh token
- Use JWT for requests
- Refresh token when expired

## 🧪 Testing

### Run all tests
```bash
./mvnw test
```

### Run specific test class
```bash
./mvnw test -Dtest=UserAuthenticationServiceTest
```

**Test Suite:**
- 60+ unit tests
- 100% passing rate
- Mockito-based service layer tests
- Full authentication workflow validation

## Documentation

- **[Rate Limiting Guide](RATE_LIMITING.md)** - Configuration and usage
- **[Docker Setup](DOCKER.md)** - Containerised deployment
- **[Security Details](docs/SECURITY.md)** - Authentication implementation
- **[API Reference](docs/API.md)** - Complete endpoint documentation

---

## 🚧 Future Improvements

- OAuth 2.0 integration (Google, GitHub)
- Two-factor authentication (TOTP)
- Product management API
- Shopping cart system
- Order processing workflow
- Stripe payment completion
- CI/CD pipeline (GitHub Actions)
- Monitoring integration (Prometheus + Grafana)� Author

**Stefano D'Incà**  
Backend Developer

[![GitHub](https://img.shields.io/badge/GitHub-@Byrontec2018-black?logo=github)](https://github.com/Byrontec2018)

---

## 📝 License

MIT License - see [LICENSE.txt](LICENSE.txt) for details.

---

**Version 1.0.0** •
