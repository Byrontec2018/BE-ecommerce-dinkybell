package com.dinkybell.ecommerce.authentication.service;

import java.time.LocalDateTime;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import com.dinkybell.ecommerce.shared.dto.APIResponseDTO;

/**
 * Factory for building standardized API responses.
 *
 * Centralizes response construction logic to eliminate duplication across service classes.
 */
public final class ApiResponseFactory {

    private ApiResponseFactory() {
        // Utility class - no instantiation
    }

    /**
     * Builds a standardized API response with the given parameters.
     *
     * @param status HTTP status code
     * @param message Human-readable message
     * @param data Optional response data payload
     * @param errors Optional list of error messages
     * @return ResponseEntity with APIResponseDTO
     */
    public static ResponseEntity<APIResponseDTO<Object>> buildResponse(HttpStatus status,
            String message, Object data, List<String> errors) {
        if (status == null) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }
        return ResponseEntity.status(status)
                .body(APIResponseDTO.<Object>builder()
                        .status(status.value())
                        .message(message)
                        .data(data)
                        .errors(errors)
                        .timestamp(LocalDateTime.now())
                        .build());
    }
}
