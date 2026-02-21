package com.dinkybell.ecommerce.authentication.exception;

/**
 * Exception thrown when attempting to register with an email that already exists.
 * 
 * This exception is used during user registration to prevent duplicate email accounts.
 */
public class EmailAlreadyExistsException extends RuntimeException {

    public EmailAlreadyExistsException(String email) {
        super("Email already exists: " + email);
    }
}
