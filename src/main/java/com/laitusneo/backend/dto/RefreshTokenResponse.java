package com.laitusneo.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * RefreshTokenResponse DTO - Response object for token refresh
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
public class RefreshTokenResponse {

    /**
     * New JWT access token
     */
    private String accessToken;

    /**
     * Token type (usually "Bearer")
     */
    @Builder.Default
    private String tokenType = "Bearer";

    /**
     * Token expiration time in seconds
     */
    private Long expiresIn;
}