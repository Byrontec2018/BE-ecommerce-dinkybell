package com.dinkybell.ecommerce;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main entry point for the Dinkybell Ecommerce application.
 * 
 * This Spring Boot application provides a RESTful API for the Dinkybell ecommerce platform. It
 * includes: - User authentication and authorization - Email verification - JWT token-based security
 * - PostgreSQL database integration
 */
@SpringBootApplication
public class EcommerceApplication {

	/**
	 * Main method that starts the Spring Boot application.
	 * 
	 * @param args Command line arguments passed to the application
	 */
	public static void main(String[] args) {
		SpringApplication.run(EcommerceApplication.class, args);
	}

}
