package com.dinkybell.ecommerce.services;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.dinkybell.ecommerce.dtos.JwtResponseDTO;
import com.dinkybell.ecommerce.entities.UserAuthentication;
import com.dinkybell.ecommerce.repositories.UserAuthenticationRepository;
import com.dinkybell.ecommerce.utils.JwtUtil;

/**
 * Service responsible for authentication operations including user registration, email
 * confirmation, and login with JWT token generation.
 * 
 * This service manages the complete authentication flow for users in the Dinkybell e-commerce
 * platform, including: - User registration with email verification - Password hashing and security
 * - Email confirmation process - JWT-based authentication - Login tracking
 */
@Service
public class UserAuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(UserAuthenticationService.class);

    /** Repository for accessing and managing user authentication data */
    @Autowired
    UserAuthenticationRepository authenticationRepository;

    /** Encoder for hashing and validating passwords */
    @Autowired
    PasswordEncoder passwordEncoder;

    /** Service for sending email notifications */
    @Autowired
    private JavaMailSender mailSender;

    /** Utility for JWT token generation and validation */
    @Autowired
    private JwtUtil jwtUtil;

    /** JWT token expiration time in milliseconds from application properties */
    @Value("${jwt.expiration}")
    private long jwtExpiration;

    /** Service for managing blacklisted tokens */
    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    /**
     * Registers a new user in the system with email and password.
     * 
     * @param email The email address of the user
     * @param password The plain text password (will be hashed before storage)
     * @return ResponseEntity with success message or error details
     */
    public ResponseEntity<?> registerUser(String email, String password) {

        // Check if email already exists
        if (authenticationRepository.existsByEmail(email)) {
            return ResponseEntity.badRequest().body("Email already exists");
        }

        // Create hashed password using BCrypt
        String hashedPassword = passwordEncoder.encode(password);

        // Generate secure random token for email confirmation
        String emailConfirmToken = UUID.randomUUID().toString();

        // Create new user authentication entity
        UserAuthentication userAuthentication = new UserAuthentication();
        userAuthentication.setEmail(email);
        userAuthentication.setPassword(hashedPassword);
        userAuthentication.setEmailConfirmToken(emailConfirmToken);
        userAuthentication.setEmailConfirmTokenExpiry(LocalDateTime.now().plusMinutes(15)); // Token
                                                                                            // expires
                                                                                            // after
                                                                                            // 15
                                                                                            // minutes

        try {
            // Persist user to database
            UserAuthentication savedUser = authenticationRepository.save(userAuthentication);

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
            e.printStackTrace();
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
            System.out.println("Email sent successfully");
            return "Confirmation email sent successfully";
        } catch (org.springframework.mail.MailAuthenticationException e) {
            // Handle authentication failures (wrong username/password)
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
     * @return ResponseEntity containing JWT token or error message
     */
    public ResponseEntity<?> loginUser(String email, String password) {
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

            // Record the login timestamp
            authentication.setLastLogin(LocalDateTime.now());

            // Update user record with login time
            authenticationRepository.save(authentication);

            // Get token expiration date from the token itself
            Date tokenExpirationTime = jwtUtil.extractExpirationDate(token);

            // Return JWT token and relevant information
            return ResponseEntity
                    .ok(new JwtResponseDTO(token, authentication.getEmail(), tokenExpirationTime));
        } catch (Exception e) {
            // Log the error and return generic message
            e.printStackTrace();
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
                    logger.info("Logout attempt with already invalidated token. JTI: {}", jti);
                    return ResponseEntity.ok().body("Token was already invalidated");
                }

                Date expiryDate = jwtUtil.extractExpirationDate(token);
                String email = jwtUtil.extractEmail(token);

                logger.info("User with email {} is logging out", email);

                // Add token to blacklist
                tokenBlacklistService.blacklistToken(jti, expiryDate);

                logger.info("Successfully invalidated token for user {}", email);
                return ResponseEntity.ok().body("Logout successful");
            } catch (Exception e) {
                // Token is invalid or already expired
                logger.warn("Invalid token provided during logout attempt: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid token");
            }
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Logout failed: " + e.getMessage());
        }
    }
}
