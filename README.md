# 🛍️ Dinkybell E-commerce Platform

A handcrafted, custom-built e-commerce platform developed in **Java + Spring Boot**, designed to support the online sale of handmade polymer clay jewellery from the **dinkybell** brand. Includes an integrated **Blog section** to express creativity and share ideas.

---

## 🚀 Key Features

- Secure user registration with email confirmation
- JWT-based authentication using RS256 algorithm
- **Refresh token system with multi-device support**
- **Device fingerprinting for enhanced security**
- **Automatic token rotation and cleanup**
- Product and category management
- Cart and order system
- PostgreSQL database integration
- Secure CRUD operations with Spring Security
- Built-in Blog module
- RESTful architecture ready for React frontend integration
- Payment service with STRIPE

---

## 🧱 Technology Stack

| Component       | Technology                    |
| --------------- | ----------------------------- |
| Backend         | Java 21                       |
| Framework       | Spring Boot 3.5.4, Spring MVC |
| Security        | Spring Security, JWT (jjwt)   |
| Database        | PostgreSQL                    |
| ORM             | Spring Data JPA               |
| Email           | Spring Mail                   |
| Build Tool      | Maven 3                       |
| IDE             | Visual Studio Code            |
| API Docs        | Swagger / OpenAPI 3.0         |
| Version Control | Git + GitHub                  |

---

## ⚙️ Project Setup

### Prerequisites

- Java JDK 21+
- Maven 3.x
- PostgreSQL Server
- SMTP server access for email functionality
- Visual Studio Code with Java extensions

### Environment Variables

The application requires the following environment variables:

- `DB_PASSWORD`: PostgreSQL database password
- `MAIL_PASSWORD`: Email service password

You can set these using the provided `load-env.sh` script.

### Clone the repository

````bash
git clone https://github.com/Byrontec2018/BE-ecommerce-dinkybell.git
cd BE-ecommerce-dinkybell

### Database Setup
```sql
CREATE DATABASE ecommerce_db;
CREATE USER admin WITH ENCRYPTED PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE ecommerce_db TO admin;
````

### Running the application

```bash
# Load environment variables
source ./load-env.sh

# Build the project
./mvnw clean install

# Run the application
./mvnw spring-boot:run
```

## � Refresh Token System

The application implements a sophisticated refresh token system that provides:

### Features

- **Multi-Device Support**: Each user can maintain up to 5 active sessions across different devices
- **Device Fingerprinting**: Unique device identification prevents token duplication from the same device
- **Automatic Token Rotation**: Old tokens are automatically revoked when the limit is exceeded
- **Security Tracking**: Device information is stored for security auditing
- **Sliding Window Expiry**: Tokens are automatically cleaned up when expired or revoked

### Token Lifecycle

1. **Login**: Creates a refresh token (30-day expiry) alongside the JWT access token (5-minute expiry)
2. **Token Refresh**: Uses refresh token to generate new access tokens without re-authentication
3. **Device Detection**: Prevents duplicate tokens from the same device/browser combination
4. **Automatic Cleanup**: Expired and revoked tokens are periodically purged from the database
5. **Multi-Session Management**: Users can revoke tokens from specific devices or all other devices

### Configuration

- Access Token Expiry: **5 minutes**
- Refresh Token Expiry: **30 days**  
- Maximum Tokens per User: **5 devices**
- Rate Limiting: **Applied to refresh endpoints**

---

## �📚 API Documentation

### Authentication Endpoints

#### Register a New User

```
POST /api/v1/auth/register
```

Registers a new user and sends a confirmation email.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123"
}
```

#### Confirm Email

```
GET /api/v1/auth/confirm-email?token=your-token-here
```

Activates a user account after clicking the email confirmation link.

#### Login

```
POST /api/v1/auth/login
```

Authenticates a user and returns a JWT token.

**Request Body:**

```json
{
  "email": "user@example.com",
  "password": "SecurePassword123"
}
```

**Response:**

```json
{
  "token": "eyJhbGciOiJSUzI1NiJ9...",
  "type": "Bearer",
  "email": "user@example.com",
  "expirationTime": "2025-08-16T10:30:00"
}
```

#### Logout

```
GET /api/v1/auth/logout
```

Invalidates the current JWT token by adding it to a blacklist.

**Headers:**

```
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
```

**Response:**

```
"Logout successful"
```

### Refresh Token Endpoints

The application implements a comprehensive refresh token system that allows users to maintain sessions across multiple devices while ensuring security through token rotation and device fingerprinting.

#### Refresh Access Token

```
POST /api/v1/auth/refresh-token
```

Generates a new access token using a valid refresh token. Rate limited to prevent abuse.

**Request Body:**

```json
{
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**

```json
{
  "token": "eyJhbGciOiJSUzI1NiJ9...",
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "expirationTime": "2025-08-16T10:35:00"
}
```

#### Revoke Refresh Token

```
POST /api/v1/auth/revoke-token
```

Revokes the current refresh token, effectively logging out from the current device.

**Request Body:**

```json
{
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**

```
"Token successfully revoked"
```

#### Revoke Other Sessions

```
POST /api/v1/auth/revoke-other-sessions
```

Revokes all refresh tokens except the current one, implementing "log out from all other devices" functionality.

**Request Body:**

```json
{
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**

```
"Other sessions successfully revoked"
```

## 🔒 Security Features

- Secure password storage with BCrypt hashing
- JWT authentication using RS256 algorithm (asymmetric encryption)
- **Refresh token system with UUID-based tokens**
- **Device fingerprinting for multi-device security**
- **Automatic token cleanup and rotation**
- **Rate limiting on token refresh endpoints**
- **Maximum 5 active sessions per user**
- Email verification for new accounts
- Input validation for all endpoints
- Customized error responses

## 🧪 Testing

```bash
# Run all tests
./mvnw test

# Run specific test class
./mvnw test -Dtest=UserAuthenticationServiceTest
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE.txt file for details.
