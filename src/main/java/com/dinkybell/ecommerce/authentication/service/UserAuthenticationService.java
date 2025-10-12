package com.dinkybell.ecommerce.authentication.service;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.dinkybell.ecommerce.authentication.dto.JwtResponseDTO;
import com.dinkybell.ecommerce.authentication.dto.PasswordResetConfirmDTO;
import com.dinkybell.ecommerce.authentication.dto.PasswordResetRequestDTO;
import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.entity.RefreshToken;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;
import com.dinkybell.ecommerce.authentication.util.JwtUtil;

/**
 * Service responsible for authentication operations including user registration, email
 * confirmation, and login with JWT token generation.
 * 
 * This service manages the complete authentication flow for users in the Dinkybell e-commerce
 * platform, including: - User registration with email verification - Password hashing and security
 * - Email confirmation process - JWT-based authentication - Login tracking
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserAuthenticationService {

    /** Repository for accessing and managing user authentication data */
    private final UserAuthenticationRepository authenticationRepository;

    /** Encoder for hashing and validating passwords */
    private final PasswordEncoder passwordEncoder;

    /** Service for sending email notifications */
    private final JavaMailSender mailSender;

    /** Utility for JWT token generation and validation */
    private final JwtUtil jwtUtil;

    /** Service for managing blacklisted tokens */
    private final TokenBlacklistService tokenBlacklistService;
    
    /** Service for managing refresh tokens */
    private final RefreshTokenService refreshTokenService;

    /** JWT token expiration time in milliseconds from application properties */
    @Value("${jwt.access-token.expiration}")
    private long jwtExpiration;

    /**
     * Registers a new user in the system with email and password.
     * 
     * @param email The email address of the user
     * @param password The plain text password (will be hashed before storage)
     * @return ResponseEntity with success message or error details
     */
    public ResponseEntity<?> registerUser(String email, String password) {

        // Log the registration attempt
        log.info("Registering user with email: {}", email);

        // Check if email already exists
        if (authenticationRepository.existsByEmail(email)) {
            log.warn("Email already exists: {}", email);
            return ResponseEntity.badRequest().body("Email already exists");
        }

        // Create hashed password using Argon2id algorithm
        String hashedPassword = passwordEncoder.encode(password);

        // Generate secure random token for email confirmation
        String emailConfirmToken = UUID.randomUUID().toString();

        // Create new user authentication entity
        UserAuthentication userAuthentication = new UserAuthentication();
        userAuthentication.setEmail(email);
        userAuthentication.setPassword(hashedPassword);
        userAuthentication.setEmailConfirmToken(emailConfirmToken);
        userAuthentication.setEmailConfirmTokenExpiry(LocalDateTime.now().plusMinutes(15)); // Token expires after 15 minutes

        try {
            // Persist user to database
            UserAuthentication savedUser = authenticationRepository.save(userAuthentication);
            log.info("User registered successfully: {}", savedUser.getEmail());

            // Verify user was saved successfully
            if (savedUser != null && savedUser.getId() != null) {

                // Send confirmation email with verification link
                String messageResponse = sendConfirmationEmail(savedUser, emailConfirmToken);

                // Check if email sending failed
                if (messageResponse.contains("Error")) {
                    return ResponseEntity.badRequest().body(messageResponse);
                }

                // Return success response with instructions
                return ResponseEntity.ok(
                        "Please confirm your email, check your inbox for the confirmation link.");
            } else {
                // Database save failed without exception
                return ResponseEntity.status(500).body("Registration failed");
            }

        } catch (Exception e) {
            // Log the exception for debugging purposes
            log.error("Registration failed: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body("Registration failed: " + e.getMessage());
        }

    }

    /**
     * Sends a confirmation email to the user with a verification link.
     * 
     * @param authentication The user authentication entity
     * @param emailConfirmToken The token for email verification
     * @return Success message or error details
     */
    public String sendConfirmationEmail(UserAuthentication authentication,
            String emailConfirmToken) {

        try {
            // Generate secure HTTPS confirmation link with token
            String confirmationLink = "https://192.162.1.108:8080/api/v1/auth/confirm-email?token="
                    + emailConfirmToken;

            // Create email message with verification link
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom("support@dinkybell.com");
            message.setTo(authentication.getEmail());
            message.setSubject("Email Confirmation");
            message.setText("Please confirm your email by clicking the following link: "
                    + confirmationLink);

            // Send the email through configured mail server
            mailSender.send(message);
            log.info("Confirmation email sent successfully to {}", authentication.getEmail());
            return "Confirmation email sent successfully";
        } catch (org.springframework.mail.MailAuthenticationException e) {
            // Handle authentication failures (wrong username/password)
            log.error("Email authentication failed: {}", e.getMessage());
            return "Error: Email authentication failed - check email credentials";
        } catch (org.springframework.mail.MailSendException e) {
            // Handle SMTP configuration issues
            return "Error: Could not send email - check SMTP configuration";
        } catch (Exception e) {
            // Handle other unexpected errors
            return "Error sending confirmation email: " + e.getMessage();
        }

    }

    /**
     * Confirms a user's email using the token sent via email.
     * 
     * @param emailConfirmToken The verification token
     * @return ResponseEntity with success message or error details
     */
    public ResponseEntity<?> confirmEmail(String emailConfirmToken) {
        // Find user by confirmation token
        UserAuthentication authentication =
                authenticationRepository.findByEmailConfirmToken(emailConfirmToken);

        // Check if token exists and is not expired
        if (authentication == null
                || authentication.getEmailConfirmTokenExpiry().isBefore(LocalDateTime.now())) {
            return ResponseEntity.badRequest().body("Invalid or expired token");
        }

        // Update user as verified
        authentication.setEnabled(true); // Enable the account
        authentication.setEmailConfirmedAt(LocalDateTime.now()); // Record confirmation time
        authentication.setEmailConfirmToken(null); // Clear token for security
        authentication.setEmailConfirmTokenExpiry(null); // Clear expiry time

        // Save changes to database
        authenticationRepository.save(authentication);

        return ResponseEntity.ok("Email confirmed successfully");
    }

    /**
     * Authenticates a user and generates a JWT token for authorized access.
     * 
     * @param email User's email address
     * @param password User's password (plain text)
     * @param request The HTTP request (for device information)
     * @return ResponseEntity containing JWT token, refresh token or error message
     */
    public ResponseEntity<?> loginUser(String email, String password, HttpServletRequest request) {
        try {
            // Retrieve user from database by email
            UserAuthentication authentication =
                    authenticationRepository.findByEmail(email).orElse(null);

            // Check if user exists
            if (authentication == null) {
                return ResponseEntity.badRequest().body("Invalid email or password");
            }

            // Verify password matches stored hash
            if (!passwordEncoder.matches(password, authentication.getPassword())) {
                return ResponseEntity.badRequest().body("Invalid email or password");
            }

            // Ensure email has been confirmed
            if (!authentication.isEnabled()) {
                return ResponseEntity.badRequest().body("Email not confirmed");
            }

            // Generate JWT token with RS256 algorithm
            String token = jwtUtil.generateToken(authentication);
            // Generate refresh token
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(
                    authentication.getId(), request);                  

            // Record the login timestamp
            authentication.setLastLogin(LocalDateTime.now());

            // Update user record with login time
            authenticationRepository.save(authentication);

            // Get token expiration date from the token itself
            Date tokenExpirationTime = jwtUtil.extractExpirationDate(token);

            // Return JWT token, refresh token and relevant information
            return ResponseEntity.ok(new JwtResponseDTO(
                    token, 
                    refreshToken.getToken(),
                    authentication.getEmail(),
                    tokenExpirationTime));
        } catch (Exception e) {
            // Log the error and return generic message
            log.error("Login failed: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body("Login failed: " + e.getMessage());
        }
    }

    /**
     * Logs out a user by invalidating their JWT token.
     * 
     * This method extracts the JWT ID from the token and adds it to a blacklist, effectively
     * revoking the token until its natural expiration time.
     * 
     * @param token The JWT token to invalidate (in format "Bearer token")
     * @return ResponseEntity with success or error message
     */
    public ResponseEntity<?> logoutUser(String token) {
        try {
            // Check if token is provided
            if (token == null || token.isEmpty()) {
                log.warn("Logout attempt without token");
                return ResponseEntity.badRequest().body("No authentication token provided");
            }

            // Remove "Bearer " prefix if present
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            // Validate token format and signature
            try {
                // Extract token claims to verify it's a valid token
                String jti = jwtUtil.extractJti(token);

                // Check if token is blacklisted
                if (tokenBlacklistService.isBlacklisted(jti)) {
                    log.info("Logout attempt with already invalidated token. JTI: {}", jti);
                    return ResponseEntity.ok().body("Token was already invalidated");
                }

                Date expiryDate = jwtUtil.extractExpirationDate(token);
                String email = jwtUtil.extractEmail(token);

                log.info("User with email {} is logging out", email);

                // Add token to blacklist
                tokenBlacklistService.blacklistToken(jti, expiryDate);

                log.info("Successfully invalidated token for user {}", email);
                return ResponseEntity.ok().body("Logout successful");
            } catch (Exception e) {
                // Token is invalid or already expired
                log.warn("Invalid token provided during logout attempt: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
            }
        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Logout failed: " + e.getMessage());
        }
    }
    
    /**
     * Initiates the password reset process for a user.
     * 
     * @param request DTO containing the user's email address
     * @return ResponseEntity with success message or error details
     */
    public ResponseEntity<?> requestPasswordReset(PasswordResetRequestDTO request) {
        String email = request.getEmail();
        log.info("Password reset requested for email: {}", email);
        
        try {
            // Find user by email
            UserAuthentication authentication = authenticationRepository.findByEmail(email).orElse(null);
            
            if (authentication == null) {
                // For security reasons, we still return a success message even if the email doesn't exist
                log.info("Password reset requested for non-existent email: {}", email);
                return ResponseEntity.ok("If your email exists in our system, you will receive a password reset link");
            }
            
            // Generate secure random token
            String resetToken = UUID.randomUUID().toString();
            
            // Set token and expiry (15 minutes validity)
            authentication.setResetPasswordToken(resetToken);
            authentication.setResetPasswordTokenExpiry(LocalDateTime.now().plusMinutes(15));
            
            // Save updates to database
            authenticationRepository.save(authentication);
            
            // Send password reset email
            String messageResponse = sendPasswordResetEmail(authentication, resetToken);
            
            // Check if email sending failed
            if (messageResponse.contains("Error")) {
                log.error("Failed to send password reset email: {}", messageResponse);
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body("Failed to send password reset email. Please try again later.");
            }
            
            // Success response (intentionally vague for security)
            return ResponseEntity.ok("If your email exists in our system, you will receive a password reset link");
            
        } catch (Exception e) {
            log.error("Error in password reset request: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Password reset request failed. Please try again later.");
        }
    }
    
    /**
     * Sends a password reset email to the user with a reset link.
     * 
     * @param authentication The user authentication entity
     * @param resetToken The token for password reset
     * @return Success message or error details
     */
    private String sendPasswordResetEmail(UserAuthentication authentication, String resetToken) {
        try {
            // Generate secure HTTPS reset link with token
            String resetLink = "https://192.162.1.108:8080/reset-password?token=" + resetToken;
            
            // Create email message with reset link
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom("support@dinkybell.com");
            message.setTo(authentication.getEmail());
            message.setSubject("Password Reset Request");
            message.setText("You recently requested to reset your password. Click the following link to reset it:\n\n" +
                    resetLink + "\n\n" +
                    "This link will expire in 15 minutes.\n\n" +
                    "If you didn't request a password reset, please ignore this email or contact support if you have concerns.");
            
            // Send the email through configured mail server
            mailSender.send(message);
            log.info("Password reset email sent successfully to {}", authentication.getEmail());
            return "Password reset email sent successfully";
        } catch (org.springframework.mail.MailAuthenticationException e) {
            log.error("Email authentication failed during password reset: {}", e.getMessage());
            return "Error: Email authentication failed - check email credentials";
        } catch (org.springframework.mail.MailSendException e) {
            log.error("Failed to send password reset email - SMTP issue: {}", e.getMessage());
            return "Error: Could not send email - check SMTP configuration";
        } catch (Exception e) {
            log.error("Unexpected error sending password reset email: {}", e.getMessage(), e);
            return "Error sending password reset email: " + e.getMessage();
        }
    }
    
    /**
     * Validates the reset token and updates the user's password.
     * 
     * @param resetData DTO containing the token and new password
     * @return ResponseEntity with success message or error details
     */
    public ResponseEntity<?> resetPassword(PasswordResetConfirmDTO resetData) {
        try {
            String token = resetData.getToken();
            String newPassword = resetData.getNewPassword();
            
            // Find user by reset token
            UserAuthentication authentication = authenticationRepository.findByResetPasswordToken(token);
            
            // Check if token exists and is not expired
            if (authentication == null || 
                    authentication.getResetPasswordTokenExpiry() == null ||
                    authentication.getResetPasswordTokenExpiry().isBefore(LocalDateTime.now())) {
                log.warn("Invalid or expired password reset token used: {}", token);
                return ResponseEntity.badRequest().body("Invalid or expired token. Please request a new password reset.");
            }
            
            // Encode the new password using Argon2id algorithm
            String hashedPassword = passwordEncoder.encode(newPassword);
            
            // Update the password
            authentication.setPassword(hashedPassword);
            
            // Clear the reset token and expiry (for security)
            authentication.setResetPasswordToken(null);
            authentication.setResetPasswordTokenExpiry(null);
            
            // Save changes to database
            authenticationRepository.save(authentication);
            
            log.info("Password successfully reset for user: {}", authentication.getEmail());
            return ResponseEntity.ok("Password successfully reset. You can now log in with your new password.");
            
        } catch (Exception e) {
            log.error("Error resetting password: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Password reset failed. Please try again later.");
        }
    }
}
