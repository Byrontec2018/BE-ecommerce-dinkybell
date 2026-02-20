package com.dinkybell.ecommerce.authentication.repository;

import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;

/**
 * Repository interface for accessing and managing UserAuthentication entities.
 * 
 * This repository provides database operations for authentication-related data, including finding
 * users by email, checking email existence, and handling email confirmation tokens.
 */
public interface UserAuthenticationRepository extends JpaRepository<UserAuthentication, Long> {

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
     * Checks if a user with the given email exists and is disabled. Used to handle cases where
     * a user has registered but not yet confirmed their email.
     * 
     * @param email The email address to check
     * @return true if the email exists and is disabled, false otherwise
     */
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM UserAuthentication u WHERE u.email = :email AND u.active = false")
    boolean existsByEmailAndActiveFalse(@Param("email") String email);

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

    /**
     * Deletes all users disabled after 48 hours. This method is used for database cleanup.
     * 
     * @param now The current date/time
     * @return The number of users deleted
     */
    @Modifying
    @Query("DELETE FROM UserAuthentication t WHERE t.active = false AND t.registrationDate < :threshold")
    int deleteExpiredUsers(@Param("threshold") LocalDateTime threshold);

}
