# 🔒 Security Documentation

Complete security implementation details for Dinkybell E-Commerce Backend.

---

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [Authentication System](#authentication-system)
3. [Token Management](#token-management)
4. [Password Security](#password-security)
5. [Device Fingerprinting](#device-fingerprinting)
6. [Rate Limiting](#rate-limiting)
7. [Session Management](#session-management)
8. [Best Practices](#best-practices)

---

## Security Architecture

### Overview

The application implements a multi-layered security approach:

```
┌─────────────────────────────────────────────┐
│         HTTP Request                        │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│    1. CORS Filter                           │
│       - Origin validation                   │
│       - Allowed methods/headers             │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│    2. Rate Limiting (AOP)                   │
│       - Redis-based throttling              │
│       - Per-endpoint limits                 │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│    3. JWT Authentication Filter             │
│       - Token extraction                    │
│       - Signature validation                │
│       - Blacklist check                     │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│    4. Controller Layer                      │
│       - Input validation                    │
│       - Business logic                      │
└─────────────────────────────────────────────┘
```

---

## Authentication System

### JWT Implementation

**Algorithm:** RS256 (RSA with SHA-256)

**Key Generation:**
```java
// Dynamically generated 2048-bit RSA key pair on application startup
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(2048);
KeyPair keyPair = keyGen.generateKeyPair();
```

**Token Structure:**
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user@example.com",
    "jti": "unique-token-id",
    "iat": 1708617600,
    "exp": 1708617900
  },
  "signature": "..."
}
```

**Token Claims:**
- `sub` (subject): User email
- `jti` (JWT ID): Unique token identifier for blacklisting
- `iat` (issued at): Token creation timestamp
- `exp` (expiration): Token expiry timestamp (5 minutes from creation)

### Authentication Flow

```
┌─────────────────────────────────────────────────────┐
│ 1. User Login Request                               │
│    POST /auth/login                                 │
│    { email, password }                              │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│ 2. Credential Validation                            │
│    - Email exists?                                  │
│    - Account confirmed?                             │
│    - Password matches (Argon2id)?                   │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│ 3. Token Generation                                 │
│    JWT (5 min) + Refresh Token (30 days)            │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│ 4. Device Fingerprint                               │
│    Extract: User-Agent, IP, Headers                 │
│    Check active devices (max 5)                     │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│ 5. Store Refresh Token                              │
│    Database: token, device info, expiry             │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│ 6. Return Response                                  │
│    { token, refreshToken, expirationTime }          │
└─────────────────────────────────────────────────────┘
```

---

## Token Management

### Token Types

#### 1. Access Token (JWT)
- **Purpose:** API request authentication
- **Lifespan:** 5 minutes (configurable)
- **Storage:** Client-side (memory or secure storage)
- **Validation:** Every request via `JwtAuthFilter`

#### 2. Refresh Token
- **Purpose:** Obtain new access tokens
- **Lifespan:** 30 days
- **Storage:** Database + client-side
- **Format:** UUID v4 (128-bit entropy)
- **Security:** Device-bound, max 5 per user

#### 3. Email Confirmation Token
- **Purpose:** Account activation
- **Lifespan:** 24 hours
- **Format:** SecureRandom (256-bit entropy, Base64 encoded)

#### 4. Password Reset Token
- **Purpose:** Password recovery
- **Lifespan:** 15 minutes
- **Format:** SecureRandom (128-bit entropy, Base64 encoded)

### Token Lifecycle

#### Access Token Lifecycle
```
Generate → Use (5 min) → Expire → Refresh or Re-authenticate
                    ↓
              Manual Logout → Blacklist
```

#### Refresh Token Lifecycle
```
Generate → Store in DB → Use to refresh access token
                    ↓
              Device limit (5) → Revoke oldest
                    ↓
              30 days → Auto-expire
                    ↓
              Logout → Revoke
```

### Token Blacklisting

**Implementation:**
```java
public class BlacklistedToken {
    private String jti;           // JWT ID from token
    private String userEmail;
    private LocalDateTime expiryDate;
}
```

**Validation Process:**
1. Extract JWT from `Authorization` header
2. Validate signature and expiry
3. Extract `jti` (JWT ID)
4. Check if `jti` exists in blacklist
5. Allow/deny request

**Cleanup:**
```java
@Scheduled(cron = "0 0 2 * * ?")  // Daily at 2 AM
public void cleanupExpiredTokens() {
    blacklistRepository.deleteByExpiryDateBefore(LocalDateTime.now());
}
```

---

## Password Security

### Argon2id Implementation

**Why Argon2id?**
- Winner of Password Hashing Competition (PHC) 2015
- OWASP recommended (2023)
- Resistant to GPU cracking attacks
- Configurable memory-hard function

**Configuration:**
```java
public class Argon2PasswordEncoder implements PasswordEncoder {
    private static final int SALT_LENGTH = 16;      // 128-bit salt
    private static final int HASH_LENGTH = 32;      // 256-bit hash
    private static final int PARALLELISM = 1;       // Single thread
    private static final int MEMORY_KB = 65536;     // 64 MB
    private static final int ITERATIONS = 3;        // Time cost
}
```

**Password Requirements (Recommended):**
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 number
- At least 1 special character

**Hash Format:**
```
$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
```

### Password Reset Flow

```
1. User requests reset → POST /auth/forgot-password
                      ↓
2. Generate secure token (128-bit entropy)
                      ↓
3. Store token in database (15 min expiry)
                      ↓
4. Send email with reset link
                      ↓
5. User clicks link → Validate token
                      ↓
6. Submit new password → Hash with Argon2id
                      ↓
7. Update database + invalidate token
```

**Security Features:**
- Email enumeration prevention (always return success)
- Rate limiting: 1 request per 15 minutes
- Token single-use (deleted after reset)
- Short expiry window (15 minutes)

---

## Device Fingerprinting

### Purpose
- Prevent token reuse across different devices
- Enable multi-device session management
- Detect suspicious login patterns

### Fingerprint Components

```java
public String extractDeviceInfo(HttpServletRequest request) {
    String userAgent = request.getHeader("User-Agent");
    String acceptLanguage = request.getHeader("Accept-Language");
    String accept = request.getHeader("Accept");
    String ip = getClientIP(request);
    String secFetchSite = request.getHeader("Sec-Fetch-Site");
    
    return hashDeviceInfo(userAgent, acceptLanguage, accept, ip, secFetchSite);
}
```

**Hashed Fields:**
- User-Agent (browser/app identifier)
- Accept-Language (locale settings)
- Accept header (content negotiation)
- IP address
- Sec-Fetch-Site (request context)

### Device Limit Enforcement

**Database Schema:**
```sql
CREATE TABLE refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(255) UNIQUE NOT NULL,
    user_id BIGINT REFERENCES users(id),
    device_info VARCHAR(500),
    created_at TIMESTAMP,
    last_used_at TIMESTAMP,
    expiry_date TIMESTAMP
);
```

**Limit Logic:**
```java
// Check active devices for user
List<RefreshToken> activeTokens = repository.findByUserAndExpiryAfter(user, now);

if (activeTokens.size() >= MAX_DEVICES) {
    // Find oldest token by last_used_at
    RefreshToken oldest = activeTokens.stream()
        .min(Comparator.comparing(RefreshToken::getLastUsedAt))
        .orElseThrow();
    
    // Revoke oldest token
    repository.delete(oldest);
}
```

---

## Rate Limiting

### Implementation

**Technology:** Custom AOP + Redis

**Architecture:**
```
Request → @RateLimit annotation → CustomRateLimiterAspect
                                         ↓
                                   Redis key check
                                         ↓
                         [Allowed] → Controller
                         [Denied]  → RateLimitExceededException
                                         ↓
                         GlobalExceptionHandler → HTTP 429
```

### Configuration

**Per-Endpoint Limits:**

| Endpoint                | Limit | Window | Key Type        |
|-------------------------|-------|--------|-----------------|
| `/auth/register`        | 2     | 10 min | IP + User-Agent |
| `/auth/login`           | 3     | 5 min  | Email OR IP     |
| `/auth/forgot-password` | 1     | 15 min | Email OR IP     |
| `/refresh-token`        | 5     | 1 min  | Refresh Token   |

**Annotation Usage:**
```java
@RateLimit(
    operation = "register",
    maxRequests = 2,
    windowSeconds = 600,
    keyType = RateLimitKeyType.IP_AND_USER_AGENT
)
public ResponseEntity<?> register(@RequestBody RegisterDTO dto) {
    // ...
}
```

### Redis Key Strategy

**Key Format:**
```
rate_limit:{operation}:{identifier}
```

**Examples:**
```
rate_limit:login:user:test@example.com
rate_limit:login:ip:192.168.1.1:ua:4f8a9b2c
rate_limit:register:ip:10.0.0.5:ua:7e3d1a8f
```

**Value Structure:**
```json
{
  "count": 2,
  "firstRequest": 1708617600,
  "windowExpiry": 1708618200
}
```

### Error Response

**HTTP 429 Too Many Requests:**
```json
{
  "success": false,
  "message": "Rate limit exceeded for login. Try again in 245 seconds.",
  "error": "RATE_LIMIT_EXCEEDED",
  "retryAfterSeconds": 245,
  "timestamp": "2026-02-22T15:30:00Z"
}
```

**HTTP Headers:**
```
Retry-After: 245
X-RateLimit-Limit: 3
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1708618245
```

---

## Session Management

### Multi-Device Support

**User Story:**
- User logs in from laptop → Device 1
- User logs in from phone → Device 2
- User logs in from tablet → Device 3
- Each device has independent refresh token
- Access tokens refresh independently

**Session Tracking:**
```java
public class RefreshToken {
    private Long id;
    private String token;              // UUID
    private UserAuthentication user;
    private String deviceInfo;         // Hashed fingerprint
    private LocalDateTime createdAt;
    private LocalDateTime lastUsedAt;  // Updates on refresh
    private LocalDateTime expiryDate;  // 30 days from creation
}
```

### Session Revocation

#### 1. Logout (Current Session)
```
DELETE /auth/logout
Authorization: Bearer <jwt>
     ↓
Extract JWT ID → Add to blacklist
Extract user → Find refresh token by device fingerprint
     ↓
Delete refresh token from database
     ↓
Response: 200 OK
```

#### 2. Revoke Single Device
```
POST /revoke-token
{ "refreshToken": "..." }
     ↓
Find token in database → Verify ownership
     ↓
Delete refresh token
     ↓
Response: 200 OK
```

#### 3. Revoke Other Sessions
```
POST /revoke-other-sessions
{ "refreshToken": "..." }
     ↓
Find all user's refresh tokens EXCEPT current device
     ↓
Delete all other tokens
     ↓
Response: 200 OK
```

### Session Monitoring

**Scheduled Cleanup:**
```java
@Scheduled(cron = "0 0 3 * * ?")  // Daily at 3 AM
public void cleanupExpiredRefreshTokens() {
    int deleted = refreshTokenRepository.deleteByExpiryDateBefore(LocalDateTime.now());
    log.info("Cleaned up {} expired refresh tokens", deleted);
}
```

---

## Best Practices

### For Developers

1. **Never Log Sensitive Data**
   ```java
   // ❌ WRONG
   log.info("User password: {}", password);
   
   // ✅ CORRECT
   log.info("Password validation attempted for user: {}", email);
   ```

2. **Environment Variables**
   ```bash
   # ❌ WRONG - Hardcoded in application.yml
   spring.datasource.password=mypassword123
   
   # ✅ CORRECT - Environment variable
   spring.datasource.password=${DB_PASSWORD}
   ```

3. **Token Storage (Client-Side)**
   ```javascript
   // ❌ WRONG - localStorage (XSS vulnerable)
   localStorage.setItem('jwt', token);
   
   // ✅ CORRECT - Memory or HttpOnly cookie
   // Memory (React state)
   const [token, setToken] = useState(null);
   
   // Or HttpOnly cookie (set by backend)
   Set-Cookie: jwt=...; HttpOnly; Secure; SameSite=Strict
   ```

4. **Password Validation**
   ```java
   // Enforce strong passwords
   @Pattern(
       regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
       message = "Password must contain uppercase, lowercase, number, and special character"
   )
   private String password;
   ```

### For Production Deployment

1. **RSA Key Storage**
   - Generate keys once, store in secure keystore
   - Do NOT regenerate on every application restart
   - Use AWS KMS or similar secret management

2. **HTTPS Only**
   ```yaml
   server:
     ssl:
       enabled: true
       key-store: classpath:keystore.jks
       key-store-password: ${KEYSTORE_PASSWORD}
   ```

3. **Database Connection**
   - Use connection pooling (HikariCP configured)
   - Enable SSL for PostgreSQL connection
   - Rotate database credentials regularly

4. **Redis Security**
   ```yaml
   redis:
     password: ${REDIS_PASSWORD}
     ssl: true
   ```

5. **Rate Limiting**
   - Enable Redis persistence for rate limit counters
   - Monitor for distributed attacks
   - Adjust limits based on traffic patterns

### Security Checklist

- [ ] All endpoints require authentication (except public ones)
- [ ] JWT tokens expire within reasonable time (5-15 minutes)
- [ ] Refresh tokens are device-bound and limited
- [ ] Passwords are hashed with Argon2id
- [ ] Rate limiting is enabled on all auth endpoints
- [ ] HTTPS is enforced in production
- [ ] CORS is configured with specific origins (not `*`)
- [ ] Sensitive data is never logged
- [ ] Environment variables are used for secrets
- [ ] Token blacklisting is functional
- [ ] Email enumeration is prevented
- [ ] SQL injection is prevented (JPA/Hibernate)
- [ ] XSS protection (input validation)
- [ ] CSRF protection (stateless JWT)

---

## Security Incidents Response

### Suspected Token Compromise

**Immediate Actions:**
1. Revoke all refresh tokens for affected user
2. Blacklist all active JWT tokens (if JTI is known)
3. Force password reset
4. Notify user via email

**Code:**
```java
@Transactional
public void handleTokenCompromise(String userEmail) {
    UserAuthentication user = userRepository.findByEmail(userEmail)
        .orElseThrow();
    
    // Revoke all refresh tokens
    refreshTokenRepository.deleteByUser(user);
    
    // Blacklist active JWTs (if stored)
    // Generate password reset token
    passwordResetService.initiateReset(userEmail);
    
    // Send notification
    emailService.sendSecurityAlert(userEmail);
}
```

### Brute Force Detection

**Indicators:**
- Multiple failed login attempts from same IP
- Rate limit exceeded frequently
- Sequential account testing

**Mitigation:**
- Temporary IP ban (extend rate limit to 1 hour)
- CAPTCHA after 3 failed attempts
- Email notification to affected accounts

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [Argon2 RFC](https://www.rfc-editor.org/rfc/rfc9106.html)
- [Password Hashing Competition](https://www.password-hashing.net/)

---

**Last Updated:** February 22, 2026  
**Version:** 1.0.0
