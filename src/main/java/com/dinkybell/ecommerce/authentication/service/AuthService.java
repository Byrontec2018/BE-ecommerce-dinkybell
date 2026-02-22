package com.dinkybell.ecommerce.authentication.service;

import java.time.LocalDateTime;
import java.util.Date;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.dinkybell.ecommerce.authentication.dto.JwtResponseDTO;
import com.dinkybell.ecommerce.authentication.dto.UserAuthenticationRequestDTO;
import com.dinkybell.ecommerce.authentication.entity.RefreshToken;
import com.dinkybell.ecommerce.authentication.entity.UserAuthentication;
import com.dinkybell.ecommerce.authentication.exception.InvalidTokenException;
import com.dinkybell.ecommerce.authentication.exception.TokenAlreadyInvalidatedException;
import com.dinkybell.ecommerce.authentication.repository.UserAuthenticationRepository;
import com.dinkybell.ecommerce.authentication.util.JwtUtil;

/**
 * Service responsible for login and logout flows.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserAuthenticationRepository authenticationRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;
    private final RefreshTokenService refreshTokenService;
    private final UserRegistrationService userRegistrationService;

    /**
     * Authenticates a user and generates a JWT token for authorized access.
     * 
     * This method validates the user's credentials and, if successful, generates
     * a JWT access token and refresh token for authentication. If the credentials
     * are invalid, a BadCredentialsException is thrown and handled by the GlobalExceptionHandler.
     *
     * @param loginRequest DTO containing email and password
     * @param request The HTTP request (for device information)
     * @return ResponseEntity containing JWT token, refresh token and user information
     * @throws BadCredentialsException if the credentials are invalid (handled by GlobalExceptionHandler)
     */
    public ResponseEntity<?> loginUser(UserAuthenticationRequestDTO loginRequest, HttpServletRequest request) {
        UserAuthentication auth = authenticationRepository.findByEmail(loginRequest.getEmail()).orElse(null);

        if (auth == null || !passwordEncoder.matches(loginRequest.getPassword(), auth.getPassword())) {
            log.warn("Login failed due to invalid credentials");
            throw new BadCredentialsException("Invalid credentials");
        }

        if (!auth.isActive()) {
            log.warn("Login attempt for inactive account: {}", auth.getEmail());
            userRegistrationService.createConfirmationToken(auth);
            return userRegistrationService.saveUser(auth);
        }
        
        String accessToken = jwtUtil.generateToken(auth);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(auth.getId(), request);
        auth.setLastLogin(LocalDateTime.now());
        authenticationRepository.save(auth);
        Date tokenExpirationTime = jwtUtil.extractExpirationDate(accessToken);

        log.info("Login successful for user: {}", auth.getEmail());

        return ApiResponseFactory.buildResponse(
                HttpStatus.OK,
                "Login successful",
                new JwtResponseDTO(
                        accessToken,
                        refreshToken.getToken(),
                        auth.getEmail(),
                        tokenExpirationTime),
                null);

    }

    /**
     * Logs out a user by invalidating their JWT token.
     *
     * This method extracts the JWT token from the Authorization header, validates it,
     * and adds the JWT ID to a blacklist, effectively revoking the token until its
     * natural expiration time.
     * 
     * Exceptions are handled by the GlobalExceptionHandler:
     * - InvalidTokenException: for malformed, missing, or unparseable tokens
     * - TokenAlreadyInvalidatedException: for tokens already in the blacklist
     *
     * @param request The HTTP request containing the Authorization header
     * @return ResponseEntity with success message
     * @throws InvalidTokenException if the token is missing, malformed or cannot be parsed
     * @throws TokenAlreadyInvalidatedException if the token is already blacklisted
     */
    public ResponseEntity<?> logoutUser(HttpServletRequest request) {

        // Extract Authorization header
        String authHeader = request.getHeader("Authorization");
        
        // Validate header presence and format
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Logout attempt without valid Authorization header");
            throw new InvalidTokenException("No Authorization header found or invalid format. Expected 'Bearer <token>'");
        }

        // Extract token by removing "Bearer " prefix
        String token = authHeader.substring(7);
        
        log.debug("Attempting to log out user with token from Authorization header");

        try {
            // Extract JWT ID from token
            String jti = jwtUtil.extractJti(token);

            // Check if token is already blacklisted
            if (tokenBlacklistService.isBlacklisted(jti)) {
                log.info("Logout attempt with already invalidated token. JTI: {}", jti);
                throw new TokenAlreadyInvalidatedException(
                        "Token was already invalidated (JTI: " + jti + ")");
            }

            // Extract token expiration and user email
            Date expiryDate = jwtUtil.extractExpirationDate(token);
            String email = jwtUtil.extractEmail(token);

            log.info("User with email {} is logging out", email);

            // Add token to blacklist
            tokenBlacklistService.blacklistToken(jti, expiryDate);

            log.info("Successfully invalidated token for user {}", email);

            return ApiResponseFactory.buildResponse(
                    HttpStatus.OK,
                    "Logout successful",
                    null,
                    null);

        } catch (TokenAlreadyInvalidatedException e) {
            // Re-throw to be handled by GlobalExceptionHandler
            throw e;
        } catch (Exception e) {
            // Wrap any token parsing/validation errors as InvalidTokenException
            log.warn("Invalid token provided during logout attempt: {}", e.getMessage());
            throw new InvalidTokenException("Invalid or malformed token", e);
        }

    }

}
