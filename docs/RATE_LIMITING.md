# Rate Limiting Implementation

This project implements a comprehensive rate limiting system to prevent abuse of authenticated APIs and protect the application from brute force attacks and flooding. The implementation uses Aspect-Oriented Programming (AOP) for clean separation of concerns, Redis for distributed rate limiting, and provides detailed metrics and management capabilities.

## Features

- **Redis-based rate limiting** for distributed environments
- **In-memory fallback** when Redis is unavailable
- **IP-based and user-based** rate limiting strategies
- **Client fingerprinting** for more accurate identification of anonymous users
- **Flexible configuration** via annotations and application properties
- **Informative HTTP headers** in responses with rate limit information
- **Comprehensive metrics** for monitoring and analysis
- **Administrative endpoints** for monitoring and management
- **Enhanced security** with randomised expiration times
- **Clean separation** of rate limiting logic using AOP

## Configuration

### Maven Dependencies

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

### Redis Configuration (application.properties)

```properties
# Redis configuration for rate limiting
spring.data.redis.host=${REDIS_HOST:localhost}
spring.data.redis.port=${REDIS_PORT:6379}
spring.data.redis.password=${REDIS_PASSWORD:}
spring.data.redis.timeout=2000ms
spring.data.redis.database=0

# Rate limiting configuration
application.rate-limit.enabled=true
application.rate-limit.default-requests=10
application.rate-limit.default-window-seconds=60
application.rate-limit.default-per-ip=true
application.rate-limit.default-per-user=false
application.rate-limit.use-fingerprinting=false
application.rate-limit.use-randomization=true
application.rate-limit.randomization-range-ms=500
```

### Environment Variables

```bash
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password
```

## Usage

### @RateLimit Annotation

Apply rate limiting to any endpoint using the `@RateLimit` annotation:

```java
@RateLimit(requests = 10, windowSeconds = 60, perIp = true)
@PostMapping("/api/endpoint")
public ResponseEntity<?> someEndpoint() {
    // Implementation
}
```

### Annotation Parameters

- `requests`: Maximum number of allowed requests (default: 10)
- `windowSeconds`: Time window in seconds (default: 60)
- `keyPrefix`: Custom prefix for the key (default: method name)
- `perIp`: IP-based rate limiting (default: true)
- `perUser`: Authenticated user-based rate limiting (default: false)

## Applied Configurations

### Authentication Endpoints

1. **User Registration** (`/api/v1/auth/register`)
   - Limit: 5 requests per 5 minutes per IP
   - Prevents automated multiple registrations

2. **Login** (`/api/v1/auth/login`)
   - Limit: 10 attempts per 5 minutes per IP
   - Protects against brute force attacks

3. **Password Reset** (`/api/v1/auth/forgot-password`)
   - Limit: 3 requests per 15 minutes per IP
   - Prevents spam of reset emails

4. **Password Reset Confirmation** (`/api/v1/auth/reset-password`)
   - Limit: 5 requests per 5 minutes per IP
   - Protects against abuse of the reset process

## HTTP Headers

The system automatically adds informative headers to responses:

```
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 7
X-RateLimit-Reset: 1693420800
```

### When limit is exceeded (HTTP 429)

```json
{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Limit: 10 requests per 60 seconds",
  "retryAfter": 45
}
```

## Administrative Endpoints

### Get Overall Metrics

```bash
GET /api/v1/admin/rate-limits/metrics
```

Example response:
```json
{
  "enabled": true,
  "uptime": 3600000,
  "endpoints": {
    "UserAuthenticationController.login": {
      "totalChecks": 120,
      "allowed": 115,
      "blocked": 5,
      "limit": 10,
      "blockRate": 0.042
    }
  },
  "config": {
    "enabled": true,
    "defaultRequests": 10,
    "defaultWindowSeconds": 60,
    "useFingerprinting": false
  }
}
```

### Get Endpoint-Specific Metrics

```bash
GET /api/v1/admin/rate-limits/metrics/{endpoint}
```

Example response:
```json
{
  "endpoint": "UserAuthenticationController.login",
  "totalChecks": 120,
  "allowed": 115,
  "blocked": 5,
  "limit": 10,
  "activeLimits": {
    "UserAuthenticationController.login:ip:192.168.1.100": {
      "count": 3,
      "resetIn": 245,
      "resetAt": 1693420800
    }
  }
}
```

### Reset All Metrics

```bash
DELETE /api/v1/admin/rate-limits/metrics
```

### Legacy Endpoints (Deprecated)

```bash
GET /api/v1/admin/rate-limit/info/{key}
DELETE /api/v1/admin/rate-limit/reset/{key}
```

## Key Examples

Rate limiting keys follow these patterns:

- **Per IP**: `UserAuthenticationController.login:ip:192.168.1.100`
- **Per user**: `UserAuthenticationController.someMethod:user:user@example.com`
- **Per client fingerprint**: `UserAuthenticationController.login:client:a1b2c3d4e5f6`
- **Global**: `UserAuthenticationController.someMethod:global`

## Monitoring

### Logging

The system generates informative logs for:
- Rate limit violations (WARN)
- Rate limit checks (DEBUG)
- Redis connection errors (ERROR)

### Metrics

Rate limits can be monitored through:
- Application logs
- Administrative endpoints
- Redis monitoring (if used)

## Fallback

In case of Redis unavailability, the system automatically uses an in-memory implementation. This ensures the application continues to function even without Redis, although with limitations in distributed environments.

## Best Practices

1. **Redis Configuration**: Always use Redis in production for distributed environments
2. **Monitoring**: Use the new metrics API to identify potential attacks and traffic patterns
3. **Tuning**: Adjust limits based on actual application traffic observed in metrics
4. **Error Handling**: The system is designed to "fail open" in case of errors to avoid blocking legitimate traffic
5. **Security**: Enable client fingerprinting in high-security environments
6. **Randomization**: Keep randomization enabled to prevent timing attacks
7. **Clean Shutdown**: The system will properly clean up resources on shutdown
8. **Proper Key Structure**: Use the RateLimitKeyBuilder for consistent key structure

## Troubleshooting

### Redis unavailable
- Application works with in-memory fallback
- Check Redis configuration and connectivity
- Monitor logs for Redis connection errors

### Rate limits too restrictive
- Use administrative endpoints for manual resets
- Adjust @RateLimit annotation parameters
- Check metrics to identify patterns of legitimate traffic being blocked

### Performance
- Redis is optimized for rate limiting operations
- In-memory fallback has minimal overhead
- Use metrics to identify potential bottlenecks

### Debugging
- Enable DEBUG level logging for rate limit components
- Check metrics for unexpected block rates
- Use the admin API to investigate specific rate limit keys
- Temporary disable rate limiting with `application.rate-limit.enabled=false` for testing
