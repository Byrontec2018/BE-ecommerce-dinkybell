# Copilot Instructions for Dinkybell E-commerce Backend

## Architecture Overview

This is a Spring Boot 3.5.4 e-commerce backend (Java 21) implementing a sophisticated JWT authentication system with refresh tokens, rate limiting, and device fingerprinting for multi-session management.

### Key Security Features

- **JWT with RS256**: Dynamically generated 2048-bit RSA keys on startup in `JwtUtil`
- **Argon2id Password Hashing**: Custom `Argon2PasswordEncoder` (PHC 2015 winner, OWASP recommended)
- **Refresh Token System**: UUID-based tokens with device fingerprinting (max 5 devices per user)
- **Token Blacklisting**: Immediate invalidation on logout via `TokenBlacklistService`
- **Redis-based Rate Limiting**: Custom AOP implementation in `CustomRateLimiterAspect`

## Critical Patterns

### Authentication Flow
1. Login generates JWT (5min) + refresh token (30 days)
2. Device fingerprinting prevents duplicate tokens from same browser
3. `JwtAuthFilter` validates tokens and handles expiry with specific headers
4. Logout adds JWT to blacklist, keeping it invalid until natural expiry

### Rate Limiting Strategy
- Uses custom AOP (`CustomRateLimiterAspect`) instead of default Resilience4j
- Key generation: `{operation}:user:{email}` or `{operation}:ip:{ip}:ua:{hash}`
- Configured per endpoint: login (3/5min), register (2/10min), resetPassword (1/15min)
- Fallback methods return HTTP 429 with retry headers

### Refresh Token Lifecycle
```java
// Device fingerprinting components in RefreshTokenService.extractDeviceInfo():
// - User-Agent hash, Accept-Language, Accept header, IP, Sec-Fetch-Site
// Automatic token rotation when 5-device limit exceeded
// Repository queries handle active token counting and device deduplication
```

## Development Workflows

### Build & Test Commands
```bash
./mvnw clean install                    # Full build
./mvnw spring-boot:run                  # Development server
./mvnw test                             # Run tests
source ./setenv.sh                      # Load environment variables
```

### Database Schema Management
- JPA `ddl-auto: update` for development
- Entities use Lombok `@Data` annotations
- Custom queries in repositories use `@Query` with JPQL
- Automatic cleanup: `@Scheduled` methods in services

### Configuration Patterns

#### Environment Variables Required
```yaml
DB_PASSWORD, MAIL_PASSWORD, REDIS_PASSWORD (optional)
```

#### JWT Configuration
```yaml
jwt:
  access-token.expiration: 300000    # 5 minutes (testing)
  refresh-token.expiration: 2592000000  # 30 days
```

## Project-Specific Conventions

### Package Structure (Transitioning to Feature-Based)
**Target Structure**: `com.dinkybell.ecommerce.{feature}.*`
- `authentication/`: Login, JWT, refresh tokens, rate limiting
- `user/`: User management, profiles, preferences  
- `product/`: Product catalog, categories, inventory
- `order/`: Shopping cart, order processing, payments
- `shared/`: Common utilities, configurations, DTOs

**Current Legacy Structure** (being migrated):
- `configurations/`: Security, AOP aspects, custom encoders
- `controllers/`: REST endpoints with rate limiting annotations  
- `services/`: Business logic with `@Transactional` methods
- `repositories/`: JPA repositories with custom JPQL queries
- `utils/`: JWT utilities, standalone helpers
- `dtos/`: Request/response objects with validation annotations

### Exception Handling Strategy
- Custom exceptions: `RefreshTokenException` for token operations
- Services return `ResponseEntity<?>` with detailed error messages
- Global exception handling for consistent API responses
- Security exceptions logged but not exposed to prevent information leakage

### Security Implementation Notes
- RSA keys generated on startup (consider keystore for production)
- Device fingerprinting balances security vs. usability (IP changes handled)
- Token blacklisting persists across app restarts (database-backed)
- Rate limiting uses Redis with in-memory fallback

### Code Style Patterns
- Extensive Javadoc on public methods with parameter descriptions
- **Constructor injection with Lombok `@RequiredArgsConstructor`** (migrating from field injection)
- **Private final fields** for all dependencies
- Logging with SLF4J, debug level for security operations
- Constants for configuration values (`ITERATIONS`, `MEMORY_KB` in Argon2)

## Integration Points

### External Dependencies
- **PostgreSQL**: Primary data store with custom indexes on `token_blacklist.expiryDate`
- **Redis**: Rate limiting storage (graceful degradation if unavailable)
- **SMTP**: Email confirmation/password reset (Hostinger configuration)

### Cross-Component Communication
- `JwtUtil` shared between authentication and filter chains
- `RefreshTokenService` integrates with `UserAuthenticationService` for login flow
- `TokenBlacklistService` used by both logout and JWT validation filter
- Rate limiting aspect intercepts controller methods via annotations

## Testing & Debugging

### Key Debug Points
- JWT token validation in `JwtAuthFilter.doFilterInternal()`
- Rate limiting key generation in `RateLimiterKeyConfig.resolveKey()`
- Device fingerprinting logic in `RefreshTokenService.extractDeviceInfo()`
- Token blacklisting check in `JwtUtil.validateToken()`

### Common Issues
- Token expiry returns specific headers (`X-Token-Expired: true`) for frontend handling
- Rate limiting bypassed if Redis unavailable (check logs for fallback)
- Refresh token reuse prevented by device deduplication (updates `lastUsedAt`)
- CORS configuration in `SecurityConfig` for frontend integration
