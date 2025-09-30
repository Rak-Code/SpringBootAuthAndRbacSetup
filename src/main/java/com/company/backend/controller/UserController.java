package com.company.backend.controller;

import com.company.backend.config.CustomUserDetails;
import com.company.backend.dto.ApiResponse;
import com.company.backend.dto.RegisterRequest;
import com.company.backend.dto.UserResponse;
import com.company.backend.entity.User;
import com.company.backend.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

/**
 * UserController - REST controller for user management
 * Admin-only endpoints for managing users
 *
 * REUSABILITY:
 * This controller is reusable across different projects
 * Modify role-based access as needed
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "User Management", description = "User Management APIs (Admin Only)")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserService userService;

    /**
     * Get all active users
     * Admin only
     *
     * @return List of users
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get All Users", description = "Get all active users (Admin only)")
    public ResponseEntity<ApiResponse<List<UserResponse>>> getAllUsers() {
        log.info("Get all users request");

        try {
            List<User> users = userService.getAllActiveUsers();
            List<UserResponse> userResponses = userService.mapToUserResponseList(users);

            return ResponseEntity.ok(
                    ApiResponse.success("Users retrieved successfully", userResponses)
            );

        } catch (Exception e) {
            log.error("Failed to get users: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve users"));
        }
    }

    /**
     * Get user by ID
     * Admin only
     *
     * @param userId User ID
     * @return User details
     */
    @GetMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get User by ID", description = "Get user details by ID (Admin only)")
    public ResponseEntity<ApiResponse<UserResponse>> getUserById(@PathVariable Long userId) {
        log.info("Get user by ID request: {}", userId);

        try {
            User user = userService.getUserById(userId);
            UserResponse userResponse = userService.mapToUserResponse(user);

            return ResponseEntity.ok(
                    ApiResponse.success("User retrieved successfully", userResponse)
            );

        } catch (IllegalArgumentException e) {
            log.error("User not found: {}", userId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(ApiResponse.error("User not found with ID: " + userId));
        } catch (Exception e) {
            log.error("Failed to get user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve user"));
        }
    }

    /**
     * Create new user
     * Admin only
     *
     * @param registerRequest User details
     * @return Created user
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Create User", description = "Create new user (Admin only)")
    public ResponseEntity<ApiResponse<UserResponse>> createUser(
            @Valid @RequestBody RegisterRequest registerRequest) {

        log.info("Create user request: {}", registerRequest.getUsername());

        try {
            CustomUserDetails currentUser = getCurrentUserDetails();
            User user = userService.createUser(registerRequest, currentUser.getId());
            UserResponse userResponse = userService.mapToUserResponse(user);

            return ResponseEntity.status(HttpStatus.CREATED)
                    .body(ApiResponse.success("User created successfully", userResponse));

        } catch (IllegalArgumentException e) {
            log.error("User creation failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(e.getMessage()));
        } catch (Exception e) {
            log.error("Failed to create user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to create user"));
        }
    }

    /**
     * Update user
     * Admin only
     *
     * @param userId        User ID
     * @param updateRequest Update details
     * @return Updated user
     */
    @PutMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Update User", description = "Update user details (Admin only)")
    public ResponseEntity<ApiResponse<UserResponse>> updateUser(
            @PathVariable Long userId,
            @Valid @RequestBody RegisterRequest updateRequest) {

        log.info("Update user request: {}", userId);

        try {
            CustomUserDetails currentUser = getCurrentUserDetails();
            User user = userService.updateUser(userId, updateRequest, currentUser.getId());
            UserResponse userResponse = userService.mapToUserResponse(user);

            return ResponseEntity.ok(
                    ApiResponse.success("User updated successfully", userResponse)
            );

        } catch (IllegalArgumentException e) {
            log.error("User update failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(e.getMessage()));
        } catch (Exception e) {
            log.error("Failed to update user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to update user"));
        }
    }

    /**
     * Update user roles
     * Admin only
     *
     * @param userId User ID
     * @param roles  New roles
     * @return Updated user
     */
    @PutMapping("/{userId}/roles")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Update User Roles", description = "Update user roles (Admin only)")
    public ResponseEntity<ApiResponse<UserResponse>> updateUserRoles(
            @PathVariable Long userId,
            @RequestBody Set<String> roles) {

        log.info("Update user roles request: {}", userId);

        try {
            CustomUserDetails currentUser = getCurrentUserDetails();
            User user = userService.updateUserRoles(userId, roles, currentUser.getId());
            UserResponse userResponse = userService.mapToUserResponse(user);

            return ResponseEntity.ok(
                    ApiResponse.success("User roles updated successfully", userResponse)
            );

        } catch (IllegalArgumentException e) {
            log.error("User roles update failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(ApiResponse.error(e.getMessage()));
        } catch (Exception e) {
            log.error("Failed to update user roles: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to update user roles"));
        }
    }

    /**
     * Delete user (soft delete)
     * Admin only
     *
     * @param userId User ID
     * @return Success message
     */
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Delete User", description = "Soft delete user (Admin only)")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable Long userId) {
        log.info("Delete user request: {}", userId);

        try {
            userService.deleteUser(userId);

            return ResponseEntity.ok(
                    ApiResponse.success("User deleted successfully")
            );

        } catch (Exception e) {
            log.error("Failed to delete user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to delete user"));
        }
    }

    /**
     * Activate user account
     * Admin only
     *
     * @param userId User ID
     * @return Success message
     */
    @PostMapping("/{userId}/activate")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Activate User", description = "Activate user account (Admin only)")
    public ResponseEntity<ApiResponse<UserResponse>> activateUser(@PathVariable Long userId) {
        log.info("Activate user request: {}", userId);

        try {
            User user = userService.activateUser(userId);
            UserResponse userResponse = userService.mapToUserResponse(user);

            return ResponseEntity.ok(
                    ApiResponse.success("User activated successfully", userResponse)
            );

        } catch (Exception e) {
            log.error("Failed to activate user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to activate user"));
        }
    }

    /**
     * Deactivate user account
     * Admin only
     *
     * @param userId User ID
     * @return Success message
     */
    @PostMapping("/{userId}/deactivate")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Deactivate User", description = "Deactivate user account (Admin only)")
    public ResponseEntity<ApiResponse<UserResponse>> deactivateUser(@PathVariable Long userId) {
        log.info("Deactivate user request: {}", userId);

        try {
            User user = userService.deactivateUser(userId);
            UserResponse userResponse = userService.mapToUserResponse(user);

            return ResponseEntity.ok(
                    ApiResponse.success("User deactivated successfully", userResponse)
            );

        } catch (Exception e) {
            log.error("Failed to deactivate user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to deactivate user"));
        }
    }

    /**
     * Lock user account
     * Admin only
     *
     * @param userId User ID
     * @return Success message
     */
    @PostMapping("/{userId}/lock")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Lock User", description = "Lock user account (Admin only)")
    public ResponseEntity<ApiResponse<UserResponse>> lockUser(@PathVariable Long userId) {
        log.info("Lock user request: {}", userId);

        try {
            User user = userService.lockUser(userId);
            UserResponse userResponse = userService.mapToUserResponse(user);

            return ResponseEntity.ok(
                    ApiResponse.success("User locked successfully", userResponse)
            );

        } catch (Exception e) {
            log.error("Failed to lock user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to lock user"));
        }
    }

    /**
     * Unlock user account
     * Admin only
     *
     * @param userId User ID
     * @return Success message
     */
    @PostMapping("/{userId}/unlock")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Unlock User", description = "Unlock user account (Admin only)")
    public ResponseEntity<ApiResponse<UserResponse>> unlockUser(@PathVariable Long userId) {
        log.info("Unlock user request: {}", userId);

        try {
            User user = userService.unlockUser(userId);
            UserResponse userResponse = userService.mapToUserResponse(user);

            return ResponseEntity.ok(
                    ApiResponse.success("User unlocked successfully", userResponse)
            );

        } catch (Exception e) {
            log.error("Failed to unlock user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to unlock user"));
        }
    }

    /**
     * Search users
     * Admin only
     *
     * @param searchTerm Search term
     * @return List of matching users
     */
    @GetMapping("/search")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Search Users", description = "Search users by term (Admin only)")
    public ResponseEntity<ApiResponse<List<UserResponse>>> searchUsers(
            @RequestParam String searchTerm) {

        log.info("Search users request with term: {}", searchTerm);

        try {
            List<User> users = userService.searchUsers(searchTerm);
            List<UserResponse> userResponses = userService.mapToUserResponseList(users);

            return ResponseEntity.ok(
                    ApiResponse.success("Search completed successfully", userResponses)
            );

        } catch (Exception e) {
            log.error("Failed to search users: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to search users"));
        }
    }

    /**
     * Get user statistics
     * Admin only
     *
     * @return User statistics
     */
    /**
     * Get user statistics
     * Admin only
     *
     * @return User statistics
     */
    @GetMapping("/statistics")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get User Statistics", description = "Get user statistics (Admin only)")
    public ResponseEntity<ApiResponse<UserService.UserStatistics>> getUserStatistics() {
        log.info("Get user statistics request");

        try {
            UserService.UserStatistics statistics = userService.getUserStatistics();

            return ResponseEntity.ok(
                    ApiResponse.success("Statistics retrieved successfully", statistics)
            );

        } catch (Exception e) {
            log.error("Failed to get user statistics: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve statistics"));
        }
    }

    /**
     * Get users by role
     * Admin only
     *
     * @param role Role name
     * @return List of users with specified role
     */
    @GetMapping("/by-role/{role}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Get Users by Role", description = "Get users with specific role (Admin only)")
    public ResponseEntity<ApiResponse<List<UserResponse>>> getUsersByRole(@PathVariable String role) {
        log.info("Get users by role request: {}", role);

        try {
            // Add ROLE_ prefix if not present
            String normalizedRole = role.startsWith("ROLE_") ? role : "ROLE_" + role;

            List<User> users = userService.getUsersByRole(normalizedRole);
            List<UserResponse> userResponses = userService.mapToUserResponseList(users);

            return ResponseEntity.ok(
                    ApiResponse.success("Users retrieved successfully", userResponses)
            );

        } catch (Exception e) {
            log.error("Failed to get users by role: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.error("Failed to retrieve users"));
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

}