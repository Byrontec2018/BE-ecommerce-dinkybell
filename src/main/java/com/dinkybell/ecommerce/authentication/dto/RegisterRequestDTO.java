package com.dinkybell.ecommerce.authentication.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

/**
 * Data Transfer Object for user registration requests.
 * 
 * This DTO captures and validates the information required to register a new user in the system. It
 * includes comprehensive validation rules to ensure data quality and security requirements are met.
 */
@Getter
@Setter
public class RegisterRequestDTO {

    /**
     * The email address for the new user account. Must be a valid email format and is required.
     * This will be used as the username for authentication.
     */
    @NotNull(message = "Email is required")
    @NotBlank(message = "Email cannot be blank")
    @Email(message = "Invalid email format")
    private String email;

    /**
     * The password for the new account. Must meet security requirements: - Between 12 and 128
     * characters - At least one uppercase letter - At least one lowercase letter - At least one
     * digit
     */
    @NotNull(message = "Password is required")
    @NotBlank(message = "Password cannot be blank")
    @Size(min = 8, max = 128, message = "Password must be between 12 and 128 characters")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).+$",
            message = "Password must contain at least one uppercase letter, one lowercase letter, and one digit")
    private String password;
}
