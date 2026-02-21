package com.dinkybell.ecommerce.shared.exception;

import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.MailSendException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.dinkybell.ecommerce.authentication.exception.EmailAlreadyExistsException;
import com.dinkybell.ecommerce.authentication.exception.EmailSendException;
import com.dinkybell.ecommerce.authentication.exception.InvalidTokenException;
import com.dinkybell.ecommerce.authentication.exception.RefreshTokenException;
import com.dinkybell.ecommerce.authentication.exception.TokenAlreadyInvalidatedException;
import com.dinkybell.ecommerce.authentication.exception.TokenExpiredException;
import com.dinkybell.ecommerce.authentication.service.ApiResponseFactory;
import com.dinkybell.ecommerce.shared.dto.APIResponseDTO;

import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import lombok.extern.slf4j.Slf4j;

/**
 * Global exception handler for the entire application.
 * 
 * This class centralizes exception handling across all controllers, providing consistent error
 * responses. It converts various exceptions into standardized APIResponseDTO objects with
 * appropriate HTTP status codes.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

        /**
         * Handles validation exceptions from request bodies and parameters.
         * 
         * This handler processes exceptions thrown when @Valid validation fails on controller
         * method parameters. It extracts all field errors and formats them into a user-friendly
         * error response.
         * 
         * @param ex The validation exception
         * @return ResponseEntity with 400 Bad Request status and detailed error information
         */
        @ExceptionHandler(MethodArgumentNotValidException.class)
        public ResponseEntity<APIResponseDTO<Object>> handleValidationExceptions(
                        MethodArgumentNotValidException ex) {

                // Extract field errors and format them as "field: error message"
                List<String> errors = ex.getBindingResult().getFieldErrors().stream()
                                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                                .toList();

                // Build a standardized error response
                return ApiResponseFactory.buildResponse(
                                HttpStatus.BAD_REQUEST,
                                "Validation failed",
                                null,
                                errors
                );

        }

        /**
         * Handles rate limit exceptions when too many requests are made to a protected endpoint.
         * 
         * This handler catches RequestNotPermitted exceptions thrown by Resilience4j's RateLimiter
         * when the configured request limit is exceeded. It returns a 429 Too Many Requests
         * response with a message indicating that the user should wait before trying again.
         * 
         * @param ex The rate limit exception
         * @return ResponseEntity with 429 Too Many Requests status and error message
         */
        @ExceptionHandler(RequestNotPermitted.class)
        public ResponseEntity<APIResponseDTO<Object>> handleRateLimit(RequestNotPermitted ex) {

                return ApiResponseFactory.buildResponse(
                                HttpStatus.TOO_MANY_REQUESTS,
                                "Rate limit exceeded. Please wait some minutes before trying again.",
                                null,
                                null
                );

        }

        /**
         * Handles custom rate limit exceeded exceptions with detailed information.
         * 
         * This handler catches RateLimitExceededException thrown by the custom Redis-based
         * rate limiter when the configured request limit is exceeded. It returns a 429 Too
         * Many Requests response with detailed information about the rate limit violation,
         * including the Retry-After header indicating when the client can retry.
         * 
         * @param ex The rate limit exceeded exception with metadata
         * @return ResponseEntity with 429 Too Many Requests status, Retry-After header, and error details
         */
        @ExceptionHandler(RateLimitExceededException.class)
        public ResponseEntity<APIResponseDTO<Object>> handleRateLimitExceeded(RateLimitExceededException ex) {

                log.warn("Rate limit exceeded for limiter '{}': max {} requests, retry after {} seconds",
                        ex.getLimiterName(), ex.getMaxRequests(), ex.getRetryAfterSeconds());

                // Create response with Retry-After header
                HttpHeaders headers = new HttpHeaders();
                headers.add("Retry-After", String.valueOf(ex.getRetryAfterSeconds()));
                
                APIResponseDTO<Object> body = APIResponseDTO.<Object>builder()
                                .status(HttpStatus.TOO_MANY_REQUESTS.value())
                                .message("Rate limit exceeded. Please wait before trying again.")
                                .data(null)
                                .errors(List.of(String.format("Maximum %d requests allowed. Retry after %d seconds.",
                                        ex.getMaxRequests(), ex.getRetryAfterSeconds())))
                                .timestamp(java.time.LocalDateTime.now())
                                .build();

                return new ResponseEntity<>(body, headers, HttpStatus.TOO_MANY_REQUESTS);

        }

        /**
         * Handles authentication exceptions related to email sending.
         * 
         * This handler catches MailAuthenticationException and MailSendException thrown by the
         * email service when there are issues with email configuration or sending. It returns a
         * 500 Internal Server Error response with details about the email failure.
         * 
         * @param ex The mail authentication or sending exception
         * @return ResponseEntity with 500 Internal Server Error status and error message
         */
        @ExceptionHandler(MailAuthenticationException.class)
        public ResponseEntity<APIResponseDTO<Object>> handleMailAuth(MailAuthenticationException ex) {

                return ApiResponseFactory.buildResponse(
                                HttpStatus.INTERNAL_SERVER_ERROR,
                                "Email authentication failed",
                                null,
                                List.of(ex.getMessage())
                );
                        
        }

        /**
         * Handles exceptions related to email sending failures.
         * 
         * This handler catches MailSendException thrown by the email service when there are issues
         * with sending emails. It returns a 500 Internal Server Error response with details about
         * the email failure.
         * 
         * @param ex
         * @return
         */
        @ExceptionHandler(MailSendException.class)
        public ResponseEntity<APIResponseDTO<Object>> handleMailSend(MailSendException ex) {

                return ApiResponseFactory.buildResponse(
                                HttpStatus.INTERNAL_SERVER_ERROR,
                                "Failed to send email",
                                null,
                                List.of(ex.getMessage())
                );

        }

        /**
         * Handles authentication failures due to invalid credentials.
         * 
         * This handler catches BadCredentialsException thrown when a user provides
         * incorrect email or password during login. It returns a 401 Unauthorized
         * response with a generic message to avoid revealing whether the email exists.
         * 
         * @param ex The bad credentials exception
         * @return ResponseEntity with 401 Unauthorized status and error message
         */
        @ExceptionHandler(BadCredentialsException.class)
        public ResponseEntity<APIResponseDTO<Object>> handleBadCredentials(BadCredentialsException ex) {

                log.warn("Authentication failed: {}", ex.getMessage());

                return ApiResponseFactory.buildResponse(
                                HttpStatus.UNAUTHORIZED,
                                "Invalid credentials",
                                null,
                                List.of("Invalid email or password")
                );

        }

        /**
         * Handles invalid token exceptions during logout operations.
         * 
         * This handler catches InvalidTokenException thrown when a malformed or
         * invalid JWT token is provided during logout. It returns a 400 Bad Request
         * response with details about the token validation failure.
         * 
         * @param ex The invalid token exception
         * @return ResponseEntity with 400 Bad Request status and error message
         */
        @ExceptionHandler(InvalidTokenException.class)
        public ResponseEntity<APIResponseDTO<Object>> handleInvalidToken(InvalidTokenException ex) {

                log.warn("Invalid token provided: {}", ex.getMessage());

                return ApiResponseFactory.buildResponse(
                                HttpStatus.BAD_REQUEST,
                                "Invalid token format",
                                null,
                                List.of(ex.getMessage())
                );

        }

        /**
         * Handles email already exists exceptions during user registration.
         * 
         * This handler catches EmailAlreadyExistsException thrown when a user
         * attempts to register with an email that is already in use. It returns
         * a 409 Conflict response with details about the duplicate email.
         * 
         * @param ex The email already exists exception
         * @return ResponseEntity with 409 Conflict status and error message
         */
        @ExceptionHandler(EmailAlreadyExistsException.class)
        public ResponseEntity<APIResponseDTO<Object>> handleEmailAlreadyExists(EmailAlreadyExistsException ex) {

                log.warn("Email registration conflict: {}", ex.getMessage());

                return ApiResponseFactory.buildResponse(
                                HttpStatus.CONFLICT,
                                "Email already exists",
                                null,
                                List.of(ex.getMessage())
                );

        }

        /**
         * Handles token expired exceptions for email confirmation and password reset.
         * 
         * This handler catches TokenExpiredException thrown when a user attempts to
         * use an expired confirmation or reset token. It returns a 400 Bad Request
         * response prompting the user to request a new token.
         * 
         * @param ex The token expired exception
         * @return ResponseEntity with 400 Bad Request status and error message
         */
        @ExceptionHandler(TokenExpiredException.class)
        public ResponseEntity<APIResponseDTO<Object>> handleTokenExpired(TokenExpiredException ex) {

                log.warn("Token expired: {}", ex.getMessage());

                return ApiResponseFactory.buildResponse(
                                HttpStatus.BAD_REQUEST,
                                "Token expired",
                                null,
                                List.of(ex.getMessage())
                );

        }

        /**
         * Handles email sending failures.
         * 
         * This handler catches EmailSendException thrown when the system fails to
         * send confirmation or password reset emails. It returns a 500 Internal Server
         * Error response with details about the email failure.
         * 
         * @param ex The email send exception
         * @return ResponseEntity with 500 Internal Server Error status and error message
         */
        @ExceptionHandler(EmailSendException.class)
        public ResponseEntity<APIResponseDTO<Object>> handleEmailSend(EmailSendException ex) {

                log.error("Email sending failed: {}", ex.getMessage());

                return ApiResponseFactory.buildResponse(
                                HttpStatus.INTERNAL_SERVER_ERROR,
                                "Failed to send email",
                                null,
                                List.of(ex.getMessage())
                );

        }

        /**
         * Handles refresh token exceptions.
         * 
         * This handler catches RefreshTokenException thrown during refresh token operations
         * including invalid, expired, or revoked tokens. It returns a 400 Bad Request response
         * with details about the refresh failure.
         * 
         * @param ex The refresh token exception
         * @return ResponseEntity with 400 Bad Request status and error message
         */
        @ExceptionHandler(RefreshTokenException.class)
        public ResponseEntity<APIResponseDTO<Object>> handleRefreshTokenException(RefreshTokenException ex) {

                log.warn("Refresh token operation failed: {}", ex.getMessage());

                return ApiResponseFactory.buildResponse(
                                HttpStatus.BAD_REQUEST,
                                "Refresh token operation failed",
                                null,
                                List.of(ex.getMessage())
                );

        }

        /**
         * Handles token already invalidated exceptions during logout operations.
         * 
         * This handler catches TokenAlreadyInvalidatedException thrown when attempting
         * to logout with a token that is already blacklisted. It returns a 200 OK
         * response since the desired state (token invalidated) is already achieved.
         * 
         * @param ex The token already invalidated exception
         * @return ResponseEntity with 200 OK status and informational message
         */
        @ExceptionHandler(TokenAlreadyInvalidatedException.class)
        public ResponseEntity<APIResponseDTO<Object>> handleTokenAlreadyInvalidated(TokenAlreadyInvalidatedException ex) {

                log.info("Logout attempt with already invalidated token: {}", ex.getMessage());

                return ApiResponseFactory.buildResponse(
                                HttpStatus.OK,
                                "Token was already invalidated",
                                null,
                                null
                );

        }

        /** 
         * Handles any uncaught exceptions that occur in the application.
         * 
         * This handler catches all exceptions that are not explicitly handled by other
         * exception handlers. It returns a 500 Internal Server Error response with a
         * generic error message.
         * 
         * @param ex The uncaught exception
         * @return ResponseEntity with 500 Internal Server Error status and error message
         */
        @ExceptionHandler(Exception.class)
        public ResponseEntity<APIResponseDTO<Object>> handleGeneric(Exception ex) {

                log.error("Exception class: {}", ex.getClass().getName());

                return ApiResponseFactory.buildResponse(
                                HttpStatus.INTERNAL_SERVER_ERROR,
                                "Unexpected server error",
                                null,
                                List.of("Internal error")
                );

        }
}
