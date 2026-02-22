# 📡 API Documentation

Complete API reference for Dinkybell E-Commerce Backend.

---

## Table of Contents

1. [Base Configuration](#base-configuration)
2. [Authentication Endpoints](#authentication-endpoints)
3. [Token Management](#token-management)
4. [Password Management](#password-management)
5. [Error Handling](#error-handling)
6. [Testing Workflows](#testing-workflows)

---

## Base Configuration

### Base URL
```
http://localhost:8080/api/v1
```

**Production:** `https://api.dinkybell.com/api/v1`

### Authentication Header

All protected endpoints require a JWT token in the `Authorization` header:

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Response Format

All API responses follow a consistent structure:

#### Success Response (2xx)
```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": {
    "id": 1,
    "email": "user@example.com"
  },
  "timestamp": "2026-02-22T15:30:00Z"
}
```

#### Error Response (4xx, 5xx)
```json
{
  "success": false,
  "message": "Descriptive error message",
  "error": "ERROR_CODE",
  "timestamp": "2026-02-22T15:30:00Z"
}
```

### Rate Limiting Headers

When rate limits are enforced, responses include:

```http
X-RateLimit-Limit: 3
X-RateLimit-Remaining: 2
X-RateLimit-Reset: 1708618245
Retry-After: 245
```

---

## Authentication Endpoints

### 1. User Registration

Create a new user account with email verification.

**Endpoint:** `POST /auth/register`

**Rate Limit:** 2 requests per 10 minutes (per IP + User-Agent)

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Validation Rules:**
- Email: Valid format, unique
- Password: Minimum 8 characters (recommendation: uppercase, lowercase, number, special char)

**Example:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "johndoe@example.com",
    "password": "MySecure@Pass2026"
  }'
```

**Success Response (201 Created):**
```json
{
  "success": true,
  "message": "Registration successful. Please check your email to confirm your account.",
  "data": null,
  "timestamp": "2026-02-22T15:30:00Z"
}
```

**Error Responses:**

| Status | Error Code                | Message                             |
|--------|---------------------------|-------------------------------------|
| 400    | INVALID_EMAIL             | Email format is invalid             |
| 400    | WEAK_PASSWORD             | Password does not meet requirements |
| 409    | EMAIL_EXISTS              | Email address already registered    |
| 429    | RATE_LIMIT_EXCEEDED       | Too many registration attempts      |
| 503    | EMAIL_SERVICE_UNAVAILABLE | Unable to send confirmation email   |

---

### 2. Email Confirmation

Activate user account by confirming email address.

**Endpoint:** `GET /auth/confirm-email`

**Rate Limit:** None (single-use token)

**Query Parameters:**
| Parameter | Type   | Required | Description                   |
|-----------|--------|----------|-------------------------------|
| token     | String | Yes      | Confirmation token from email |

**Example:**
```bash
curl -X GET "http://localhost:8080/api/v1/auth/confirm-email?token=a7b2c9d4e1f3g8h5i6j7k8l9m0n1o2p3"
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Email confirmed successfully. Your account is now active.",
  "data": null,
  "timestamp": "2026-02-22T15:31:00Z"
}
```

**Error Responses:**

| Status | Error Code        | Message                                  |
|--------|-------------------|------------------------------------------|
| 400    | INVALID_TOKEN     | Confirmation token is invalid or expired |
| 404    | TOKEN_NOT_FOUND   | Token does not exist                     |
| 409    | ALREADY_CONFIRMED | Email already confirmed                  |

---

### 3. User Login

Authenticate user and receive JWT + refresh token.

**Endpoint:** `POST /auth/login`

**Rate Limit:** 3 requests per 5 minutes (per email OR IP)

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "johndoe@example.com",
    "password": "MySecure@Pass2026"
  }'
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huZG9lQGV4YW1wbGUuY29tIiwianRpIjoiYTdiMmM5ZDRlMWYzZzhoNSIsImlhdCI6MTcwODYxNzYwMCwiZXhwIjoxNzA4NjE3OTAwfQ...",
    "refreshToken": "a7c4d2e9-f1b3-4c8a-9e2d-5b7c3a1f8e6d",
    "type": "Bearer",
    "email": "johndoe@example.com",
    "expirationTime": "2026-02-22T15:35:00Z"
  },
  "timestamp": "2026-02-22T15:30:00Z"
}
```

**Response Fields:**
- `token`: JWT access token (5-minute expiry)
- `refreshToken`: UUID for token refresh (30-day expiry)
- `type`: Always "Bearer"
- `email`: Authenticated user email
- `expirationTime`: ISO 8601 timestamp when JWT expires

**Error Responses:**

| Status | Error Code            | Message                         |
|--------|-----------------------|---------------------------------|
| 401    | INVALID_CREDENTIALS   | Email or password is incorrect  |
| 403    | ACCOUNT_NOT_CONFIRMED | Please confirm your email first |
| 403    | ACCOUNT_DISABLED      | Your account has been disabled  |
| 429    | RATE_LIMIT_EXCEEDED   | Too many login attempts         |

---

### 4. Logout

Invalidate current JWT token and refresh token.

**Endpoint:** `GET /auth/logout`

**Authentication:** Required (Bearer token)

**Rate Limit:** None

**Headers:**
```http
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

**Example:**
```bash
curl -X GET http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Successfully logged out",
  "data": null,
  "timestamp": "2026-02-22T15:40:00Z"
}
```

**What Happens:**
1. JWT ID (`jti`) added to blacklist table
2. Refresh token for current device deleted
3. Token becomes immediately invalid

**Error Responses:**

| Status | Error Code        | Message                            |
|--------|-------------------|------------------------------------|
| 401    | INVALID_TOKEN     | JWT token is invalid or expired    |
| 401    | TOKEN_BLACKLISTED | Token has already been invalidated |

---

## Token Management

### 5. Refresh Access Token

Obtain a new JWT using a valid refresh token.

**Endpoint:** `POST /refresh-token`

**Rate Limit:** 5 requests per minute (per refresh token)

**Request Body:**
```json
{
  "refreshToken": "a7c4d2e9-f1b3-4c8a-9e2d-5b7c3a1f8e6d"
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/v1/refresh-token \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "a7c4d2e9-f1b3-4c8a-9e2d-5b7c3a1f8e6d"
  }'
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Token refreshed successfully",
  "data": {
    "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.NEW_TOKEN...",
    "refreshToken": "a7c4d2e9-f1b3-4c8a-9e2d-5b7c3a1f8e6d",
    "type": "Bearer",
    "email": "johndoe@example.com",
    "expirationTime": "2026-02-22T16:05:00Z"
  },
  "timestamp": "2026-02-22T16:00:00Z"
}
```

**Notes:**
- Refresh token remains the same
- `lastUsedAt` timestamp updated in database
- New JWT generated with fresh expiry

**Error Responses:**

| Status | Error Code            | Message                             |
|--------|-----------------------|-------------------------------------|
| 400    | INVALID_REFRESH_TOKEN | Refresh token is invalid or expired |
| 404    | TOKEN_NOT_FOUND       | Refresh token does not exist        |
| 429    | RATE_LIMIT_EXCEEDED   | Too many refresh attempts           |

---

### 6. Revoke Refresh Token

Manually invalidate a specific refresh token.

**Endpoint:** `POST /revoke-token`

**Rate Limit:** None

**Request Body:**
```json
{
  "refreshToken": "a7c4d2e9-f1b3-4c8a-9e2d-5b7c3a1f8e6d"
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/v1/revoke-token \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "a7c4d2e9-f1b3-4c8a-9e2d-5b7c3a1f8e6d"
  }'
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Token successfully revoked",
  "data": null,
  "timestamp": "2026-02-22T16:10:00Z"
}
```

**Use Case:** User wants to log out from a specific device remotely.

**Error Responses:**

| Status | Error Code            | Message                                 |
|--------|-----------------------|-----------------------------------------|
| 400    | INVALID_REFRESH_TOKEN | Token is invalid                        |
| 404    | TOKEN_NOT_FOUND       | Token does not exist or already revoked |

---

### 7. Revoke Other Sessions

Log out from all devices except the current one.

**Endpoint:** `POST /revoke-other-sessions`

**Rate Limit:** None

**Request Body:**
```json
{
  "refreshToken": "a7c4d2e9-f1b3-4c8a-9e2d-5b7c3a1f8e6d"
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/v1/revoke-other-sessions \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "a7c4d2e9-f1b3-4c8a-9e2d-5b7c3a1f8e6d"
  }'
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "All other sessions successfully revoked. 3 tokens invalidated.",
  "data": {
    "revokedCount": 3
  },
  "timestamp": "2026-02-22T16:15:00Z"
}
```

**What Happens:**
1. Identify user from provided refresh token
2. Find all refresh tokens for that user
3. Delete all tokens EXCEPT the one provided
4. Current device remains logged in

**Use Case:** User suspects account compromise and wants to secure their account.

**Error Responses:**

| Status | Error Code            | Message                  |
|--------|-----------------------|--------------------------|
| 400    | INVALID_REFRESH_TOKEN | Current token is invalid |
| 404    | TOKEN_NOT_FOUND       | Token does not exist     |

---

## Password Management

### 8. Request Password Reset

Initiate password recovery process.

**Endpoint:** `POST /auth/forgot-password`

**Rate Limit:** 1 request per 15 minutes (per email OR IP)

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "johndoe@example.com"
  }'
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "If your email exists in our system, you will receive a password reset link shortly.",
  "data": null,
  "timestamp": "2026-02-22T16:20:00Z"
}
```

**Security Features:**
- ✅ Always returns success (prevents email enumeration)
- ✅ Email only sent if account exists
- ✅ Token expires after 15 minutes
- ✅ Single-use token (deleted after reset)

**Email Content:**
```
Subject: Password Reset Request

Hello,

You requested a password reset for your Dinkybell account.

Click here to reset your password:
http://localhost:8080/reset-password?token=abc123def456

This link expires in 15 minutes.

If you didn't request this, please ignore this email.
```

**Error Responses:**

| Status | Error Code                | Message                 |
|--------|---------------------------|-------------------------|
| 429    | RATE_LIMIT_EXCEEDED       | Too many reset requests |
| 503    | EMAIL_SERVICE_UNAVAILABLE | Unable to send email    |

---

### 9. Reset Password

Complete password reset with token.

**Endpoint:** `POST /auth/reset-password`

**Rate Limit:** None (single-use token)

**Request Body:**
```json
{
  "token": "a7b2c9d4e1f3g8h5i6j7k8l9",
  "newPassword": "NewSecurePass123!"
}
```

**Example:**
```bash
curl -X POST http://localhost:8080/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "a7b2c9d4e1f3g8h5i6j7k8l9",
    "newPassword": "MyNew@SecurePass2026"
  }'
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Password successfully reset. You can now log in with your new password.",
  "data": null,
  "timestamp": "2026-02-22T16:25:00Z"
}
```

**What Happens:**
1. Validate token exists and not expired
2. Hash new password with Argon2id
3. Update user password in database
4. Delete reset token (single-use)
5. Optionally: Revoke all refresh tokens

**Error Responses:**

| Status | Error Code      | Message                                 |
|--------|-----------------|-----------------------------------------|
| 400    | INVALID_TOKEN   | Reset token is invalid or expired       |
| 400    | WEAK_PASSWORD   | New password does not meet requirements |
| 404    | TOKEN_NOT_FOUND | Token does not exist                    |

---

## Error Handling

### Standard Error Codes

| Code                        | HTTP Status | Description                    |
|-----------------------------|-------------|--------------------------------|
| `INVALID_CREDENTIALS`       | 401         | Login credentials incorrect    |
| `INVALID_TOKEN`             | 401         | JWT or refresh token invalid   |
| `TOKEN_EXPIRED`             | 401         | JWT has expired (use refresh)  |
| `TOKEN_BLACKLISTED`         | 401         | Token was invalidated (logout) |
| `ACCOUNT_NOT_CONFIRMED`     | 403         | Email not verified             |
| `ACCOUNT_DISABLED`          | 403         | Account suspended              |
| `EMAIL_EXISTS`              | 409         | Email already registered       |
| `RATE_LIMIT_EXCEEDED`       | 429         | Too many requests              |
| `EMAIL_SERVICE_UNAVAILABLE` | 503         | SMTP service down              |
| `INVALID_EMAIL`             | 400         | Email format invalid           |
| `WEAK_PASSWORD`             | 400         | Password too weak              |
| `TOKEN_NOT_FOUND`           | 404         | Token doesn't exist            |

### Rate Limit Error (429)

```json
{
  "success": false,
  "message": "Rate limit exceeded for login. Try again in 245 seconds.",
  "error": "RATE_LIMIT_EXCEEDED",
  "retryAfterSeconds": 245,
  "timestamp": "2026-02-22T16:30:00Z"
}
```

**Headers:**
```http
HTTP/1.1 429 Too Many Requests
Retry-After: 245
X-RateLimit-Limit: 3
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1708618445
```

### Validation Error (400)

```json
{
  "success": false,
  "message": "Validation failed",
  "error": "VALIDATION_ERROR",
  "details": {
    "email": "Email format is invalid",
    "password": "Password must be at least 8 characters"
  },
  "timestamp": "2026-02-22T16:32:00Z"
}
```

---

## Testing Workflows

### Complete Authentication Flow

**Step 1: Register User**
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!@#"
  }'
```

**Step 2: Confirm Email**
```bash
# Check email for confirmation link
# Extract token from email
curl -X GET "http://localhost:8080/api/v1/auth/confirm-email?token=YOUR_TOKEN_HERE"
```

**Step 3: Login**
```bash
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!@#"
  }')

echo $LOGIN_RESPONSE | jq
```

**Step 4: Extract Tokens (using jq)**
```bash
JWT=$(echo $LOGIN_RESPONSE | jq -r '.data.token')
REFRESH_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.data.refreshToken')

echo "JWT: $JWT"
echo "Refresh Token: $REFRESH_TOKEN"
```

**Step 5: Access Protected Endpoint**
```bash
curl -X GET http://localhost:8080/api/v1/users/profile \
  -H "Authorization: Bearer $JWT"
```

**Step 6: Wait for JWT Expiry (5 minutes)**
```bash
# After 5 minutes, JWT expires
# Use refresh token to get new JWT
curl -X POST http://localhost:8080/api/v1/refresh-token \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}" | jq
```

**Step 7: Logout**
```bash
curl -X GET http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer $JWT"
```

---

### Multi-Device Testing

**Simulate 3 devices:**

```bash
#!/bin/bash

# Device 1: Chrome on laptop
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0" \
  -d '{"email":"test@example.com","password":"Test123!@#"}' \
  | jq -r '.data.refreshToken' > device1_token.txt

# Device 2: Safari on iPhone
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/605.1.15" \
  -d '{"email":"test@example.com","password":"Test123!@#"}' \
  | jq -r '.data.refreshToken' > device2_token.txt

# Device 3: Firefox on tablet
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (iPad; CPU OS 17_0) Firefox/120.0" \
  -d '{"email":"test@example.com","password":"Test123!@#"}' \
  | jq -r '.data.refreshToken' > device3_token.txt

echo "3 devices logged in"

# Revoke other sessions from Device 1
DEVICE1_TOKEN=$(cat device1_token.txt)
curl -X POST http://localhost:8080/api/v1/revoke-other-sessions \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$DEVICE1_TOKEN\"}" | jq

# Try to use Device 2 token (should fail)
DEVICE2_TOKEN=$(cat device2_token.txt)
curl -X POST http://localhost:8080/api/v1/refresh-token \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$DEVICE2_TOKEN\"}" | jq
```

---

### Password Reset Flow

```bash
#!/bin/bash

# Step 1: Request password reset
curl -X POST http://localhost:8080/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com"
  }'

# Step 2: Check email for reset token
# Extract token from email link

# Step 3: Reset password
curl -X POST http://localhost:8080/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "TOKEN_FROM_EMAIL",
    "newPassword": "NewSecure@Pass2026"
  }' | jq

# Step 4: Login with new password
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "NewSecure@Pass2026"
  }' | jq
```

---

### Rate Limit Testing

```bash
#!/bin/bash

# Test login rate limit (3 per 5 minutes)
for i in {1..5}; do
  echo "Login attempt $i"
  
  RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" \
    -X POST http://localhost:8080/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"WrongPassword"}')
  
  HTTP_STATUS=$(echo "$RESPONSE" | grep "HTTP_STATUS" | cut -d: -f2)
  
  if [ "$HTTP_STATUS" == "429" ]; then
    echo "Rate limit hit on attempt $i"
    echo "$RESPONSE" | head -n -1 | jq
    break
  fi
  
  sleep 1
done
```

---

## Postman Collection

Import this JSON into Postman for easy testing:

```json
{
  "info": {
    "name": "Dinkybell E-Commerce API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "variable": [
    {
      "key": "baseUrl",
      "value": "http://localhost:8080/api/v1"
    },
    {
      "key": "jwt",
      "value": ""
    },
    {
      "key": "refreshToken",
      "value": ""
    }
  ],
  "item": [
    {
      "name": "Auth",
      "item": [
        {
          "name": "Register",
          "request": {
            "method": "POST",
            "url": "{{baseUrl}}/auth/register",
            "body": {
              "mode": "raw",
              "raw": "{\n  \"email\": \"test@example.com\",\n  \"password\": \"Test123!@#\"\n}"
            }
          }
        },
        {
          "name": "Login",
          "request": {
            "method": "POST",
            "url": "{{baseUrl}}/auth/login",
            "body": {
              "mode": "raw",
              "raw": "{\n  \"email\": \"test@example.com\",\n  \"password\": \"Test123!@#\"\n}"
            }
          },
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "const response = pm.response.json();",
                  "pm.collectionVariables.set('jwt', response.data.token);",
                  "pm.collectionVariables.set('refreshToken', response.data.refreshToken);"
                ]
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## Additional Resources

- **Swagger UI:** http://localhost:8080/swagger-ui.html
- **OpenAPI Spec:** http://localhost:8080/v3/api-docs
- **Rate Limiting Guide:** [RATE_LIMITING.md](../RATE_LIMITING.md)
- **Security Details:** [SECURITY.md](SECURITY.md)

---

**Last Updated:** February 22, 2026  
**API Version:** 1.0.0
