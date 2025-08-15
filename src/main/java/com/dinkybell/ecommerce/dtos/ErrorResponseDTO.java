package com.dinkybell.ecommerce.dtos;

import lombok.Builder;
import lombok.Data;
import java.util.List;

/**
 * Data Transfer Object for standardized error responses.
 * 
 * This DTO provides a consistent structure for error responses across the API. It includes: - A
 * status code or message - A human-readable error message - An optional list of detailed error
 * messages
 * 
 * Using the Builder pattern for flexible instantiation.
 */
@Data
@Builder
public class ErrorResponseDTO {
    /**
     * The status code or status identifier for the error. Typically matches HTTP status codes like
     * "400", "404", etc.
     */
    private String status;

    /**
     * A general error message describing the problem.
     */
    private String message;

    /**
     * A list of specific error details. Useful for validation errors where multiple fields may have
     * issues.
     */
    private List<String> errors;
}
