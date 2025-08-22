package com.dinkybell.ecommerce.dtos;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Data Transfer Object for completing the password reset process.
 * 
 * This DTO contains the necessary fields for validating a reset token
 * and setting a new password.
 */
@Data
public class PasswordResetConfirmDTO {

    /**
     * The password reset token received via email.
     */
    @NotEmpty(message = "Token is required")
    private String token;

    /**
     * The new password to set for the user account.
     */    
    @NotEmpty(message = "New password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).+$",
            message = "Password must contain at least one uppercase letter, one lowercase letter, and one digit")
    private String newPassword;
}
