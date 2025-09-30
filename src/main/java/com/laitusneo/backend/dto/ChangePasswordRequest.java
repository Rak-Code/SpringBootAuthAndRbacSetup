package com.laitusneo.backend.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * ChangePasswordRequest DTO - Request object for password change
 *
 * REUSABILITY:
 * This DTO is completely reusable across different projects
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ChangePasswordRequest {

    /**
     * Current password
     */
    @NotBlank(message = "Current password is required")
    private String currentPassword;

    /**
     * New password
     */
    @NotBlank(message = "New password is required")
    @Size(min = 8, message = "Password must be at least 8 characters long")
    private String newPassword;

    /**
     * Confirm new password
     */
    @NotBlank(message = "Password confirmation is required")
    private String confirmPassword;
}