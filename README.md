# 🛍️ Dinkybell E-commerce Platform

A handcrafted, custom-built e-commerce platform developed in **Java + Spring Boot**, designed to support the online sale of handmade polymer clay jewellery from the **dinkybell** brand. Includes an integrated **Blog section** to express creativity and share ideas.

---

## 🚀 Key Features

- Secure user registration with email confirmation
- JWT-based authentication using RS256 algorithm
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

## 📚 API Documentation

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

## 🔒 Security Features

- Secure password storage with BCrypt hashing
- JWT authentication using RS256 algorithm (asymmetric encryption)
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
