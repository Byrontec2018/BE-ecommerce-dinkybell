package com.dinkybell.ecommerce.authentication.service;

import java.time.LocalDateTime;

import com.dinkybell.ecommerce.shared.util.SecureTokenGenerator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.dinkybell.ecommerce.authentication.dto.TokenRequestDTO;
import com.dinkybell.ecommerce.authentication.dto.UserAuthenticationRequestDTO;
import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.exception.EmailAlreadyExistsException;
import com.dinkybell.ecommerce.authentication.exception.TokenExpiredException;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;

import jakarta.transaction.Transactional;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Service responsible for registration and email confirmation flows.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserRegistrationService {

    private final UserAuthenticationRepository authRepo;
    private final PasswordEncoder passwordEncoder;
    private final EmailNotificationService emailNotificationService;

    /**
     * Registers a new user in the system with email and password.
     * 
     * This method validates that the email is not already in use by an active user,
     * creates a new user account, generates an email confirmation token, and sends
     * a confirmation email. Exceptions are handled by the GlobalExceptionHandler.
     *
     * @param registerData The registration payload containing email and password
     * @return ResponseEntity with success message
     * @throws EmailAlreadyExistsException if the email is already registered by an active user
     */
    public ResponseEntity<?> registerUser(@NonNull UserAuthenticationRequestDTO registerData) {

        log.info("Registering user with email: {}", registerData.getEmail());

        UserAuthentication userAuth = new UserAuthentication();

        // Check if email exists and is active
        if (authRepo.existsByEmail(registerData.getEmail()) && !authRepo.existsByEmailAndActiveFalse(registerData.getEmail())) {
            log.warn("Email already exists: {}", registerData.getEmail());
            throw new EmailAlreadyExistsException(registerData.getEmail());
        }

        // Reuse existing unverified user if exists
        if (authRepo.existsByEmail(registerData.getEmail())) {
            log.info("Resending confirmation email to unverified user: {}", registerData.getEmail());
            userAuth = authRepo.findByEmail(registerData.getEmail()).orElse(null);
        }

        userAuth.setEmail(registerData.getEmail());
        userAuth.setPassword(passwordEncoder.encode(registerData.getPassword()));

        createConfirmationToken(userAuth);

        return saveUser(userAuth);

    }

    /**
     * Persists the user to the database and sends a confirmation email.
     *
     * @param userAuthentication The user authentication entity to save
     * @return ResponseEntity with success message or error details
     */
    @Transactional
    public ResponseEntity<?> saveUser(@NonNull UserAuthentication userAuthentication) {

        UserAuthentication savedUser = authRepo.save(userAuthentication);           

        log.info("User registered successfully: {}", savedUser.getEmail());

        emailNotificationService.sendConfirmationEmail(savedUser);        

        return ApiResponseFactory.buildResponse(
                HttpStatus.OK,
                "Please confirm your email to activate your account.", 
                null, 
                null
        );  
        
    }

    /**
     * Creates a secure confirmation token and sets it on the user entity.
     *
     * @param userAuthentication The user authentication entity
     */
    public void createConfirmationToken(UserAuthentication userAuthentication) {

        String emailConfirmToken = SecureTokenGenerator.generateShortToken(); // 128-bit token for short-lived email confirmation (5-15 min)

        userAuthentication.setEmailConfirmToken(emailConfirmToken);
        userAuthentication.setEmailConfirmTokenExpiry(LocalDateTime.now().plusMinutes(5));

    }

    /**
     * Confirms a user's email using the token sent via email.
     * 
     * This method validates the confirmation token and activates the user account.
     * Exceptions are handled by the GlobalExceptionHandler.
     *
     * @param emailConfirmToken The verification token from the email
     * @return ResponseEntity with success message
     * @throws TokenExpiredException if the token is invalid or expired
     */
    public ResponseEntity<?> confirmEmail(TokenRequestDTO emailConfirmToken) {

        log.info("Confirming email with token: {}", emailConfirmToken.getToken());

        UserAuthentication auth = authRepo.findByEmailConfirmToken(emailConfirmToken.getToken());

        if (auth == null || auth.getEmailConfirmTokenExpiry().isBefore(LocalDateTime.now())) {
            log.warn("Invalid or expired email confirmation token: {}", emailConfirmToken.getToken());
            throw new TokenExpiredException("Invalid or expired confirmation token. Please request a new one.");
        }

        auth.setActive(true);
        auth.setEmailConfirmedAt(LocalDateTime.now());
        auth.setEmailConfirmToken(null);
        auth.setEmailConfirmTokenExpiry(null);

        authRepo.save(auth);

        return ApiResponseFactory.buildResponse(
                HttpStatus.OK,
                "Email confirmed successfully",
                null,
                null
        );

    }

}
