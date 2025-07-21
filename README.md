# 🛍️ Dinkybell E-commerce Platform

A handcrafted, custom-built e-commerce platform developed in **Java + Spring Boot**, designed to support the online sale of handmade polymer clay jewellery from the **dinkybell** brand. Includes an integrated **Blog section** to express creativity and share ideas.

---

## 🚀 Key Features

- Product and category management
- User registration and login (JWT-based)
- Cart and order system
- MySQL database integration
- Secure CRUD operations with Spring Security
- Built-in Blog module
- RESTful architecture ready for React frontend integration
- Payment service with STRIPE

---

## 🧱 Technology Stack

| Component         | Technology                 |
|-------------------|----------------------------|
| Backend           | Java 17                    |
| Framework         | Spring Boot 3, Spring MVC  |
| Security          | Spring Security, JWT       |
| Database          | MySQL 8                    |
| ORM               | Spring Data JPA            |
| Build Tool        | Maven 3                    |
| IDE               | Visual Studio Code         |
| API Docs          | Swagger / OpenAPI 3.0      |
| Version Control   | Git + GitHub               |

---

## ⚙️ Project Setup

### Prerequisites
- Java JDK 17+
- Maven 3.x
- MySQL Server
- Visual Studio Code with Java extensions

### Clone the repository
```bash
git clone https://github.com/your-username/ecommerce-dinkybell.git
cd ecommerce-dinkybell
Configure the database
Create a database named ecommerce_db

Update your src/main/resources/application.properties:
properties
Copia
Modifica
spring.datasource.url=jdbc:mysql://localhost:3306/ecommerce_db
spring.datasource.username=root
spring.datasource.password=your_password
Run the application
bash
Copia
Modifica
./mvnw spring-boot:run

## 🔐 Authentication & Security
Protected endpoints require a valid JWT token
Custom login flow via Spring Security
Role-based access: USER, ADMIN

## 📚 API Documentation
Available via Swagger at:
bash
Copia
Modifica
http://localhost:8080/swagger-ui/index.html

## ✍️ Blog Section
Integrated blog system with full CRUD functionality, image support, and author metadata.

## 🧾 License
This project is released under a Proprietary License.
All rights reserved © 2025 Byrontec by Stefano D’Incà (dinkybell).
For permissions or enquiries, please contact: stefano.dinca@byrontec.com

## 💡 Final Notes
This is an ongoing full-stack project. The backend is built with Spring Boot, and the REST API is fully prepared for integration with a future React frontend.
