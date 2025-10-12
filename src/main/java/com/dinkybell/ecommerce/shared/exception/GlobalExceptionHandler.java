package com.dinkybell.ecommerce.shared.exception;

import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.dinkybell.ecommerce.shared.dto.ErrorResponseDTO;

/**
 * Global exception handler for the entire application.
 * 
 * This class centralizes exception handling across all controllers, providing consistent error
 * responses. It converts various exceptions into standardized ErrorResponseDTO objects with
 * appropriate HTTP status codes.
 */
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
        public ResponseEntity<ErrorResponseDTO> handleValidationExceptions(
                        MethodArgumentNotValidException ex) {

                // Extract field errors and format them as "field: error message"
                List<String> errors = ex.getBindingResult().getFieldErrors().stream()
                                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                                .toList();

                // Build a standardized error response
                ErrorResponseDTO errorResponse = ErrorResponseDTO.builder().status("error")
                                .message("Validation failed").errors(errors).build();

                return ResponseEntity.badRequest().body(errorResponse);
        }
}
