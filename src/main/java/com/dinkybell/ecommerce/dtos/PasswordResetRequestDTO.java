package com.dinkybell.ecommerce.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

/**
 * Data Transfer Object for password reset requests.
 * 
 * This DTO captures the email address needed to initiate a password reset
 * process.
 */
@Data
public class PasswordResetRequestDTO {

    /**
     * The email address of the user requesting password reset.
     */
    @NotEmpty(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;
}
