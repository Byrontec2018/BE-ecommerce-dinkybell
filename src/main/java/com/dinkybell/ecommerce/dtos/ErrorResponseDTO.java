package com.dinkybell.ecommerce.dtos;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class ErrorResponseDTO {
    private String status;
    private String message;
    private List<String> errors;
}
