package com.laitusneo.backend.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * RefreshTokenRequest DTO - Request object for token refresh
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
public class RefreshTokenRequest {

    /**
     * Refresh token
     */
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}