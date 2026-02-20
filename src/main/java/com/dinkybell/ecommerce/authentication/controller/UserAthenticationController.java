package com.dinkybell.ecommerce.authentication.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import jakarta.servlet.http.HttpServletRequest;

import com.dinkybell.ecommerce.authentication.dto.PasswordResetConfirmDTO;
import com.dinkybell.ecommerce.authentication.dto.PasswordResetRequestDTO;
import com.dinkybell.ecommerce.authentication.dto.TokenRequestDTO;
import com.dinkybell.ecommerce.authentication.dto.UserAuthenticationRequestDTO;
import com.dinkybell.ecommerce.authentication.service.UserLoginService;
import com.dinkybell.ecommerce.authentication.service.PasswordResetService;
import com.dinkybell.ecommerce.authentication.service.UserRegistrationService;
import lombok.RequiredArgsConstructor;
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
@RequiredArgsConstructor
@Slf4j
public class UserAthenticationController {
    
    private final UserLoginService userLoginService;
    private final UserRegistrationService userRegistrationService;
    private final PasswordResetService passwordResetService;

    /**
     * Handles user registration requests.
     * 
     * This endpoint creates a new user account and sends a confirmation email with a verification
     * link that must be clicked to activate the account.
     * 
     * @param registerRequest DTO containing email and password
     * @return ResponseEntity with success message or error details
     */
    @RateLimiter(name = "register")
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid UserAuthenticationRequestDTO registerRequest) {  

        return userRegistrationService.registerUser(registerRequest);

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
    public ResponseEntity<?> confirmEmail(@RequestParam TokenRequestDTO token) {  

        return userRegistrationService.confirmEmail(token);

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
    @RateLimiter(name = "login")
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid UserAuthenticationRequestDTO loginRequest, HttpServletRequest request) {

        return userLoginService.loginUser(loginRequest, request);

    }

    /**
     * Handles user logout requests.
     * 
     * This endpoint invalidates the user's JWT token by adding it to a blacklist, preventing
     * further use of the token until its natural expiration time. The token must be provided
     * in the Authorization header as "Bearer <token>".
     * 
     * @param request The HTTP request containing the Authorization header with the JWT token
     * @return ResponseEntity with success message or error details
     */
    @GetMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {

        return userLoginService.logoutUser(request);

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
    @RateLimiter(name = "resetPassword")
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody @Valid PasswordResetRequestDTO requestDTO) {

        return passwordResetService.requestPasswordReset(requestDTO);

    }
    
    /**
     * Handles password reset confirmation.
     * 
     * This endpoint validates the reset token and sets the new password if the token is valid.
     * 
     * @param resetDTO DTO containing the token and new password
     * @return ResponseEntity with success message or error details
     */
    @RateLimiter(name = "confirmResetPassword")
    //@PostMapping("/reset-password")
    //public ResponseEntity<?> resetPassword(@RequestBody @Valid PasswordResetConfirmDTO resetDTO) {
    @GetMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestParam String newPassword) {
        PasswordResetConfirmDTO resetDTO = new PasswordResetConfirmDTO();
        resetDTO.setToken(token);
        resetDTO.setNewPassword(newPassword);
        return passwordResetService.resetPassword(resetDTO);
    }    
 
}
