package com.dinkybell.ecommerce.authentication.exception;

/**
 * Exception thrown when refresh token operations fail.
 * 
 * This exception is used for various refresh token related errors including:
 * - Invalid refresh token format
 * - Expired refresh tokens
 * - Revoked refresh tokens
 * - Missing refresh tokens
 */
public class RefreshTokenException extends RuntimeException {
    
    /**
     * Constructs a new refresh token exception with the specified detail message.
     * 
     * @param message the detail message explaining the reason for the exception
     */
    public RefreshTokenException(String message) {
        super(message);
    }
    
    /**
     * Constructs a new refresh token exception with the specified detail message and cause.
     * 
     * @param message the detail message explaining the reason for the exception
     * @param cause the cause of the exception
     */
    public RefreshTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}