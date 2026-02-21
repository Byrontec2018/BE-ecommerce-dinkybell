package com.dinkybell.ecommerce.authentication.exception;

/**
 * Exception thrown when a JWT token is invalid or malformed.
 * 
 * This exception is used during logout operations when the provided token
 * cannot be parsed or validated properly.
 */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
