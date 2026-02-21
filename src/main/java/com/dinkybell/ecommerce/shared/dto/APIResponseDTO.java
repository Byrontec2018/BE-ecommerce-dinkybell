package com.dinkybell.ecommerce.shared.dto;

import java.time.LocalDateTime;
import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Data Transfer Object for standardized API responses.
 * 
 * This DTO provides a consistent structure for all API responses across the Dinkybell e-commerce
 * platform. It wraps response data in a uniform envelope that includes:
 * - A status code indicating success or failure (HTTP status codes)
 * - A human-readable message describing the outcome
 * - An optional data payload containing the response data for successful requests
 * - An optional error message for failed requests
 * - A timestamp indicating when the response was generated
 * 
 * The generic type parameter {@code <T>} allows this DTO to be used for any type of response data,
 * making it versatile across different API endpoints (user data, product data, order data, etc.).
 * 
 * Using the Builder pattern for flexible instantiation and ease of use in service layers.
 * 
 * @param <T> The type of data payload contained in the response
 */
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class APIResponseDTO<T> {
    
    /**
     * HTTP status code indicating the result of the request.
     * Examples: 200 (OK), 201 (Created), 400 (Bad Request), 404 (Not Found), 500 (Server Error)
     */
    private int status;
    
    /**
     * Human-readable message describing the outcome of the request.
     * Examples: "User created successfully", "Invalid credentials", "Resource not found"
     */
    private String message;
    
    /**
     * The actual data payload for successful responses.
     * This can be any type (User, Product, List of items, etc.) based on the generic parameter T.
     * Null if the request failed or no data is returned.
     */
    private T data;
    
    /**
     * Detailed error message for failed requests.
     * Contains specific error information for debugging and client-side error handling.
     * Null if the request was successful.
     */
    private List<String> errors;
    
    /**
     * Timestamp indicating when the response was generated.
     * Useful for caching, logging, and debugging purposes.
     */
    private LocalDateTime timestamp;
}
