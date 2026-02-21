package com.dinkybell.ecommerce.authentication.exception;

/**
 * Exception thrown when a token (email confirmation or password reset) has expired.
 * 
 * This exception is used when users try to use expired confirmation or reset tokens.
 */
public class TokenExpiredException extends RuntimeException {

    public TokenExpiredException(String message) {
        super(message);
    }
}
