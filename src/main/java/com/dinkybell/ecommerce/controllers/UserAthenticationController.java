package com.dinkybell.ecommerce.controllers;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.dinkybell.ecommerce.dtos.PasswordResetConfirmDTO;
import com.dinkybell.ecommerce.dtos.PasswordResetRequestDTO;
import com.dinkybell.ecommerce.dtos.UserAuthenticationRequestDTO;
import com.dinkybell.ecommerce.services.UserAuthenticationService;

import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import jakarta.validation.Valid;

/**
 * REST Controller for handling authentication-related endpoints.
 * 
 * This controller exposes the API endpoints for: - User registration - Email confirmation - User
 * login with JWT token generation
 * 
 * All endpoints are mapped under the "/api/v1/auth" base path.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class UserAthenticationController {

    /** Service that handles user authentication business logic */
    @Autowired
    private UserAuthenticationService userAuthenticationService;

    /**
     * Handles user registration requests.
     * 
     * This endpoint creates a new user account and sends a confirmation email with a verification
     * link that must be clicked to activate the account.
     * 
     * @param registerRequest DTO containing email and password
     * @return ResponseEntity with success message or error details
     */
    @RateLimiter(name = "register", fallbackMethod = "registerFallback")
    @PostMapping("/register")
    public ResponseEntity<?> register(
            @RequestBody @Valid UserAuthenticationRequestDTO registerRequest) {
        // Call the service to register the user
        return userAuthenticationService.registerUser(registerRequest.getEmail(),
                registerRequest.getPassword());
    }

    /**
     * Handles email confirmation requests.
     * 
     * This endpoint is accessed when a user clicks the confirmation link in their email. It
     * verifies the token and activates the user account if the token is valid.
     * 
     * @param token The confirmation token sent in the email
     * @return ResponseEntity with success message or error details
     */
    @GetMapping("/confirm-email")
    public ResponseEntity<?> confirmEmail(@RequestParam String token) {
        System.out.println("Confirming email with token: " + token);
        return userAuthenticationService.confirmEmail(token);
    }

    /**
     * Handles user login requests.
     * 
     * This endpoint authenticates a user and generates a JWT token for authenticated API access. It
     * only succeeds if the account exists, is active (email confirmed), and the credentials are
     * valid.
     * 
     * @param loginRequest DTO containing email and password credentials
     * @return ResponseEntity with JWT token or error details
     */
    @RateLimiter(name = "login", fallbackMethod = "loginFallback")
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid UserAuthenticationRequestDTO loginRequest) {
        return userAuthenticationService.loginUser(loginRequest.getEmail(),
                loginRequest.getPassword());
    }

    /**
     * Handles user logout requests.
     * 
     * This endpoint invalidates the user's JWT token by adding it to a blacklist, preventing
     * further use of the token until its natural expiration time.
     * 
     * @param authHeader The Authorization header containing the JWT token
     * @return ResponseEntity with success message or error details
     */
    @GetMapping("/logout")
    public ResponseEntity<?> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        return userAuthenticationService.logoutUser(authHeader);
    }
    
    /**
     * Handles password reset requests.
     * 
     * This endpoint initiates the password reset process by sending a reset link
     * to the user's email address if it exists in the system.
     * 
     * @param requestDTO DTO containing the user's email address
     * @return ResponseEntity with success message or error details
     */
    @RateLimiter(name = "resetPassword", fallbackMethod = "resetPasswordFallback")
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody @Valid PasswordResetRequestDTO requestDTO) {
        return userAuthenticationService.requestPasswordReset(requestDTO);
    }
    
    /**
     * Handles password reset confirmation.
     * 
     * This endpoint validates the reset token and sets the new password if the token is valid.
     * 
     * @param resetDTO DTO containing the token and new password
     * @return ResponseEntity with success message or error details
     */
    @RateLimiter(name = "confirmResetPassword", fallbackMethod = "confirmResetPasswordFallback")
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody @Valid PasswordResetConfirmDTO resetDTO) {
        return userAuthenticationService.resetPassword(resetDTO);
    }

    // ============================================
    // Fallback Methods for Rate Limiting
    // ============================================

    /**
     * Fallback method for register endpoint when rate limit is exceeded.
     */
    public ResponseEntity<?> registerFallback(UserAuthenticationRequestDTO registerRequest, RequestNotPermitted ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of(
            "error", "Registration rate limit exceeded",
            "message", "Too many registration attempts. Please wait 10 minutes before trying again.",
            "code", "REGISTRATION_RATE_LIMIT_EXCEEDED",
            "suggestedWaitTime", "600 seconds"
        ));
    }

    /**
     * Fallback method for login endpoint when rate limit is exceeded.
     */
    public ResponseEntity<?> loginFallback(UserAuthenticationRequestDTO loginRequest, RequestNotPermitted ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of(
            "error", "Login rate limit exceeded",
            "message", "Too many login attempts. Please wait 5 minutes before trying again.",
            "code", "LOGIN_RATE_LIMIT_EXCEEDED",
            "suggestedWaitTime", "300 seconds"
        ));
    }

    /**
     * Fallback method for forgot password endpoint when rate limit is exceeded.
     */
    public ResponseEntity<?> resetPasswordFallback(PasswordResetRequestDTO requestDTO, RequestNotPermitted ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of(
            "error", "Password reset rate limit exceeded",
            "message", "Too many password reset requests. Please wait 15 minutes before trying again.",
            "code", "PASSWORD_RESET_RATE_LIMIT_EXCEEDED",
            "suggestedWaitTime", "900 seconds"
        ));
    }

    /**
     * Fallback method for reset password confirmation endpoint when rate limit is exceeded.
     */
    public ResponseEntity<?> confirmResetPasswordFallback(PasswordResetConfirmDTO resetDTO, RequestNotPermitted ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of(
            "error", "Password reset confirmation rate limit exceeded",
            "message", "Too many password reset confirmation attempts. Please wait 10 minutes before trying again.",
            "code", "PASSWORD_RESET_CONFIRMATION_RATE_LIMIT_EXCEEDED",
            "suggestedWaitTime", "600 seconds"
        ));
    }

}
