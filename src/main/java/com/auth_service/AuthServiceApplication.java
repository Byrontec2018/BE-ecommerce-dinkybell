package com.auth_service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Main entry point for the Authentication Service application.
 * 
 * This Spring Boot application provides a RESTful API for the Authentication Service module. It
 * includes: - User authentication and authorization - Email verification - JWT token-based security
 * - PostgreSQL database integration
 * 
 * @EnableScheduling is used to enable scheduling capabilities for the blacklist token cleanup.
 */
@SpringBootApplication
@EnableScheduling
public class AuthServiceApplication {

	/**
	 * Main method that starts the Spring Boot application.
	 * 
	 * @param args Command line arguments passed to the application
	 */
	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}

}
