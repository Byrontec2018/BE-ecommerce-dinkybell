package com.dinkybell.ecommerce.authentication.exception;

/**
 * Exception thrown when attempting to logout with a token that has already been invalidated.
 * 
 * This is not a critical error - it indicates the token was already blacklisted
 * and the user can safely proceed as if logout was successful.
 */
public class TokenAlreadyInvalidatedException extends RuntimeException {

    public TokenAlreadyInvalidatedException(String message) {
        super(message);
    }
}
