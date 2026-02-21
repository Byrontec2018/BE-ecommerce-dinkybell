package com.dinkybell.ecommerce.authentication.exception;

/**
 * Exception thrown when an email fails to send.
 * 
 * This exception wraps email sending failures for consistent error handling.
 */
public class EmailSendException extends RuntimeException {

    public EmailSendException(String message) {
        super(message);
    }

    public EmailSendException(String message, Throwable cause) {
        super(message, cause);
    }
}
