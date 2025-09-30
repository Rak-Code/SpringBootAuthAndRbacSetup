package com.laitusneo.backend.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * RegisterRequest DTO - Request object for user registration
 *
 * REUSABILITY:
 * This DTO is completely reusable across different projects
 * Modify validation rules as needed for your project
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisterRequest {

    /**
     * Username
     */
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    /**
     * Email address
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    private String email;

    /**
     * Password
     */
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    private String password;

    /**
     * Full name
     */
    @NotBlank(message = "Full name is required")
    private String fullName;

    /**
     * Phone number (optional)
     */
    private String phoneNumber;

    /**
     * Roles to assign
     * For admin use only - regular registration should not include roles
     */
    private Set<String> roles;
}