package com.laitusneo.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * LoginResponse DTO - Response object for successful login
 *
 * REUSABILITY:
 * This DTO is completely reusable across different projects
 * Standard JWT authentication response format
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginResponse {

    /**
     * JWT access token
     */
    private String accessToken;

    /**
     * JWT refresh token
     */
    private String refreshToken;

    /**
     * Token type (usually "Bearer")
     */
    @Builder.Default
    private String tokenType = "Bearer";

    /**
     * Token expiration time in seconds
     */
    private Long expiresIn;

    /**
     * User information
     */
    private UserInfo user;

    /**
     * Nested class for user information
     */
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class UserInfo {
        private Long id;
        private String username;
        private String email;
        private String fullName;
        private Set<String> roles;
        private String status;
    }
}