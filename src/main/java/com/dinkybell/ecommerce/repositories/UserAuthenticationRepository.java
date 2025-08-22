package com.dinkybell.ecommerce.repositories;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.dinkybell.ecommerce.entities.UserAuthentication;

/**
 * Repository interface for accessing and managing UserAuthentication entities.
 * 
 * This repository provides database operations for authentication-related data, including finding
 * users by email, checking email existence, and handling email confirmation tokens.
 */
public interface UserAuthenticationRepository extends JpaRepository<UserAuthentication, Integer> {

    /**
     * Finds a user authentication record by email address.
     * 
     * @param email The email address to search for
     * @return An Optional containing the user if found, or empty if not found
     */
    Optional<UserAuthentication> findByEmail(String email);

    /**
     * Checks if a user with the given email exists.
     * 
     * @param email The email address to check
     * @return true if the email exists in the database, false otherwise
     */
    boolean existsByEmail(String email);

    /**
     * Finds a user authentication record by email confirmation token. Used during the email
     * verification process.
     * 
     * @param resetToken The confirmation token to search for
     * @return The UserAuthentication record if found, or null if not found
     */
    UserAuthentication findByEmailConfirmToken(String resetToken);
    
    /**
     * Finds a user authentication record by password reset token. 
     * Used during the password reset process.
     * 
     * @param resetToken The password reset token to search for
     * @return The UserAuthentication record if found, or null if not found
     */
    UserAuthentication findByResetPasswordToken(String resetToken);

}
