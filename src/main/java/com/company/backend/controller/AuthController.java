package com.company.backend.controller;

import com.company.backend.config.CustomUserDetails;
import com.company.backend.dto.*;
import com.company.backend.dto.*;
import com.company.backend.entity.User;
import com.company.backend.service.AuthService;
import com.company.backend.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

/**
 * AuthController - REST controller for authentication endpoints
 * Handles login, token refresh, password management, and user registration
 *
 * REUSABILITY:
 * This controller is highly reusable across different projects
 * Standard authentication endpoints that work with any JWT-based system
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Authentication and Authorization APIs")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    /**
     * User login endpoint
     * Authenticates user and returns JWT tokens
     *
     * @param loginRequest Login credentials
     * @return LoginResponse with access and refresh tokens
     */
    @PostMapping("/login")
    @Operation(summary = "User Login", description = "Authenticate user and get JWT tokens")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("Login request for user: {}", loginRequest.getUsername());

        try {
            // Authenticate and get tokens
            Map<String, Object> authResult = authService.login(
                    loginRequest.getUsername(),
                    loginRequest.getPassword()
            );

            // Build response
            LoginResponse loginResponse = buildLoginResponse(authResult);

            return ResponseEntity.ok(
                    ApiResponse.success("Login successful", loginResponse)
            );

        } catch (Exception e) {
            log.error("Login failed for user {}: {}", loginRequest.getUsername(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Login failed: " + e.getMessage()));
        }
    }

    /**
     * Refresh access token
     * Uses refresh token to generate new access token
     *
     * @param refreshRequest Refresh token request
     * @return RefreshTokenResponse with new access token
     */
    @PostMapping("/refresh")
    @Operation(summary = "Refresh Token", description = "Get new access token using refresh token")
    public ResponseEntity<ApiResponse<RefreshTokenResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest refreshRequest) {

        log.info("Token refresh request");

        try {
            Map<String, Object> refreshResult = authService.refreshToken(refreshRequest.getRefreshToken());

            RefreshTokenResponse response = RefreshTokenResponse.builder()
                    .accessToken((String) refreshResult.get("accessToken"))
                    .tokenType((String) refreshResult.get("tokenType"))
                    .expiresIn((Long) refreshResult.get("expiresIn"))
                    .build();

            return ResponseEntity.ok(
                    ApiResponse.success("Token refreshed successfully", response)
            );

        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Token refresh failed: " + e.getMessage()));
        }
    }

    /**
     * Validate token
     * Checks if token is valid and returns user info
     *
     * @param token JWT token from Authorization header
     * @return User information if token is valid
     */
    @GetMapping("/validate")
    @Operation(summary = "Validate Token", description = "Validate JWT token and get user info")
    public ResponseEntity<ApiResponse<Map<String, Object>>> validateToken(
            @RequestHeader("Authorization") String token) {

        log.debug("Token validation request");

        try {
            // Remove "Bearer " prefix if present
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            Map<String, Object> validationResult = authService.validateToken(token);

            if ((Boolean) validationResult.get("valid")) {
                return ResponseEntity.ok(
                        ApiResponse.success("Token is valid", validationResult)
                );
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.error("Token is invalid"));
            }

        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("Token validation failed: " + e.getMessage()));
        }
    }

    /**
     * Get current user information
     * Returns information about the authenticated user
     *
     * @return Current user details
     */
    @GetMapping("/me")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Get Current User", description = "Get authenticated user information")
    public ResponseEntity<ApiResponse<UserResponse>> getCurrentUser() {
        log.debug("Get current user request");

        try {
            CustomUserDetails userDetails = getCurrentUserDetails();
            User user = userService.getUserById(userDetails.getId());
            UserResponse userResponse = userService.mapToUserResponse(user);

            return ResponseEntity.ok(
                    ApiResponse.success("User retrieved successfully", userResponse)
            );

        } catch (Exception e) {
            log.error("Failed to get current user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve user information"));
        }
    }

    /**
     * Change password for authenticated user
     *
     * @param changePasswordRequest Password change request
     * @return Success message
     */
    @PostMapping("/change-password")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Change Password", description = "Change password for authenticated user")
    public ResponseEntity<ApiResponse<Void>> changePassword(
            @Valid @RequestBody ChangePasswordRequest changePasswordRequest) {

        log.info("Password change request");

        try {
            // Validate password confirmation
            if (!changePasswordRequest.getNewPassword().equals(changePasswordRequest.getConfirmPassword())) {
                return ResponseEntity.badRequest()
                        .body(ApiResponse.error("New password and confirmation do not match"));
            }

            CustomUserDetails userDetails = getCurrentUserDetails();

            authService.changePassword(
                    userDetails.getId(),
                    changePasswordRequest.getCurrentPassword(),
                    changePasswordRequest.getNewPassword()
            );

            return ResponseEntity.ok(
                    ApiResponse.success("Password changed successfully")
            );

        } catch (Exception e) {
            log.error("Password change failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error("Password change failed: " + e.getMessage()));
        }
    }

    /**
     * Register new user
     * Admin-only endpoint or can be public depending on requirements
     *
     * @param registerRequest Registration details
     * @return Created user information
     */
    @PostMapping("/register")
    @Operation(summary = "Register User", description = "Register a new user (Admin only)")
    public ResponseEntity<ApiResponse<UserResponse>> register(
            @Valid @RequestBody RegisterRequest registerRequest) {

        log.info("User registration request for username: {}", registerRequest.getUsername());

        try {
            User user = userService.registerUser(registerRequest);
            UserResponse userResponse = userService.mapToUserResponse(user);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.success("User registered successfully", userResponse));

        } catch (Exception e) {
            log.error("User registration failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error("Registration failed: " + e.getMessage()));
        }
    }

    /**
     * Logout endpoint
     * In JWT, logout is handled client-side by removing the token
     * This endpoint can be used for audit logging
     *
     * @param token JWT token from Authorization header
     * @return Success message
     */
    @PostMapping("/logout")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Logout", description = "Logout user (removes token on client side)")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestHeader("Authorization") String token) {

        log.info("Logout request");

        try {
            // Remove "Bearer " prefix if present
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            authService.logout(token);

            return ResponseEntity.ok(
                    ApiResponse.success("Logout successful")
            );

        } catch (Exception e) {
            log.error("Logout error: {}", e.getMessage());
            return ResponseEntity.ok(
                    ApiResponse.success("Logout successful")
            );
        }
    }

    // ==================== HELPER METHODS ====================

    /**
     * Get current authenticated user details
     *
     * @return CustomUserDetails of authenticated user
     */
    private CustomUserDetails getCurrentUserDetails() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return (CustomUserDetails) authentication.getPrincipal();
    }

    /**
     * Build LoginResponse from authentication result
     *
     * @param authResult Authentication result map
     * @return LoginResponse object
     */
    @SuppressWarnings("unchecked")
    private LoginResponse buildLoginResponse(Map<String, Object> authResult) {
        Map<String, Object> userMap = (Map<String, Object>) authResult.get("user");

        LoginResponse.UserInfo userInfo = LoginResponse.UserInfo.builder()
                .id(((Number) userMap.get("id")).longValue())
                .username((String) userMap.get("username"))
                .email((String) userMap.get("email"))
                .fullName((String) userMap.get("fullName"))
                .roles((Set<String>) userMap.get("roles"))
                .status((String) userMap.get("status"))
                .build();

        return LoginResponse.builder()
                .accessToken((String) authResult.get("accessToken"))
                .refreshToken((String) authResult.get("refreshToken"))
                .tokenType((String) authResult.get("tokenType"))
                .expiresIn((Long) authResult.get("expiresIn"))
                .user(userInfo)
                .build();
    }
}