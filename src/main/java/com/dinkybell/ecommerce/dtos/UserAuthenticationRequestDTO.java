package com.dinkybell.ecommerce.dtos;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

/**
 * Data Transfer Object for authentication requests.
 * 
 * This DTO captures and validates the credentials needed for both registration and login
 * operations. It includes comprehensive validation rules to ensure security requirements are met.
 */
@Data
public class UserAuthenticationRequestDTO {

    /**
     * The email address for authentication. Must be a valid email format and is required.
     */
    @NotNull(message = "Email is required")
    @NotBlank(message = "Email cannot be blank")
    @Email(message = "Invalid email format")
    private String email;

    /**
     * The password for authentication. Must meet security requirements: - Between 8 and 128
     * characters - At least one uppercase letter - At least one lowercase letter - At least one
     * digit
     */
    @NotNull(message = "Password is required")
    @NotBlank(message = "Password cannot be blank")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).+$",
            message = "Password must contain at least one uppercase letter, one lowercase letter, and one digit")
    private String password;
}
