package com.company.backend.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * LoginRequest DTO - Request object for user login
 *
 * REUSABILITY:
 * This DTO is completely reusable across different projects
 * Standard login request format
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginRequest {

    /**
     * Username or email
     * Can be either username or email address
     */
    @NotBlank(message = "Username or email is required")
    private String username;

    /**
     * User password
     */
    @NotBlank(message = "Password is required")
    private String password;

    /**
     * Remember me flag (optional)
     * Can be used to extend token validity
     */
    private Boolean rememberMe;
}