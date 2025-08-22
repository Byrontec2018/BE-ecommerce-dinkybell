package com.dinkybell.ecommerce.entities;

import java.time.LocalDateTime;
import com.dinkybell.ecommerce.enums.Role;
// import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
// import jakarta.persistence.JoinColumn;
// import jakarta.persistence.OneToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * UserAuthentication entity representing authentication-related information.
 * 
 * This entity manages all authentication aspects including: - Credentials (email, password) -
 * Account status (enabled, confirmed) - Email verification tokens - Login history - Role-based
 * permissions
 * 
 * It's designed to be separate from user profile data to allow for independent scaling and security
 * isolation.
 */
@NoArgsConstructor
@Data
@Entity
@Table(name = "users_authentication",
        uniqueConstraints = {@UniqueConstraint(columnNames = {"email"})})
// @UniqueConstraint(columnNames = {"username"})})
public class UserAuthentication {

    /**
     * The unique identifier for the authentication record.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Relationship to user profile - commented out for future implementation
    // @OneToOne(cascade = CascadeType.ALL)
    // @JoinColumn(name = "user_id", referencedColumnName = "id", nullable = true)
    // private User user;

    /**
     * Username for display and login purposes. Must be 3-20 characters, alphanumeric with
     * underscores only.
     */
    @Column(length = 20, nullable = true, unique = true)
    @Size(min = 3, max = 20)
    @Pattern(regexp = "^[a-zA-Z0-9_]+$")
    private String username;

    /**
     * Email address used for authentication and notifications. Must be unique across the system.
     */
    @Column(length = 255, nullable = false, unique = true)
    @Email
    @Size(max = 255)
    private String email;

    /**
     * Password for authentication, stored using BCrypt hashing. Plain text passwords are never
     * stored.
     */
    @Column(length = 255, nullable = false)
    private String password;

    /**
     * User's role in the system (USER, ADMIN, etc.). Determines access permissions.
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role = Role.USER;

    /**
     * Flag indicating if the account is active. Accounts are disabled until email is confirmed.
     */
    @Column(nullable = false)
    private boolean enabled = false;

    /**
     * Timestamp when the email was confirmed. Null if email hasn't been confirmed yet.
     */
    @Column(name = "email_confirmed_at")
    private LocalDateTime emailConfirmedAt;

    /**
     * Timestamp when the user registered. Set automatically by @PrePersist.
     */
    @Column(name = "registration_date", nullable = false, updatable = false)
    private LocalDateTime registrationDate;

    /**
     * Timestamp of the user's last successful login.
     */
    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    /**
     * Token for email confirmation. Used to validate email address ownership.
     */
    @Column(name = "email_confirm_token")
    private String emailConfirmToken;

    /**
     * Expiration time for the email confirmation token. Tokens are typically valid for 24-48 hours.
     */
    @Column(name = "email_confirm_token_expiry")
    private LocalDateTime emailConfirmTokenExpiry;
    
    /**
     * Token for password reset. Used to validate password reset requests.
     */
    @Column(name = "reset_password_token")
    private String resetPasswordToken;

    /**
     * Expiration time for the password reset token. Tokens are typically valid for 1 hour.
     */
    @Column(name = "reset_password_token_expiry")
    private LocalDateTime resetPasswordTokenExpiry;

    /**
     * Sets the registration date automatically when entity is first persisted.
     */
    @PrePersist
    protected void onCreate() {
        this.registrationDate = LocalDateTime.now();
    }
}
