package com.company.backend.service;

import com.company.backend.dto.RegisterRequest;
import com.company.backend.dto.UserResponse;
import com.company.backend.entity.Role;
import com.company.backend.entity.User;
import com.company.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * UserService - Business logic for user management
 * Handles user CRUD operations, role management, and user queries
 *
 * REUSABILITY:
 * This service is highly reusable across different projects
 * Modify role assignments and validation rules as needed
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Register new user
     * Creates a new user account with specified roles
     *
     * @param registerRequest Registration details
     * @return Created User entity
     */
    @Transactional
    public User registerUser(RegisterRequest registerRequest) {
        log.info("Registering new user: {}", registerRequest.getUsername());

        // Validate username uniqueness
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            log.warn("Username already exists: {}", registerRequest.getUsername());
            throw new IllegalArgumentException("Username already exists");
        }

        // Validate email uniqueness
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            log.warn("Email already exists: {}", registerRequest.getEmail());
            throw new IllegalArgumentException("Email already exists");
        }

        // Determine roles
        Set<String> roles = determineRoles(registerRequest.getRoles());

        // Create user entity
        User user = User.builder()
                .username(registerRequest.getUsername())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .fullName(registerRequest.getFullName())
                .phoneNumber(registerRequest.getPhoneNumber())
                .roles(String.join(",", roles))
                .status("ACTIVE")
                .passwordChangeRequired(false)
                .passwordExpiresAt(LocalDateTime.now().plusMonths(3)) // 3 months validity
                .failedLoginAttempts(0)
                .deleted(false)
                .build();

        User savedUser = userRepository.save(user);
        log.info("User registered successfully: {} with roles: {}", savedUser.getUsername(), roles);

        return savedUser;
    }

    /**
     * Create user with admin privileges
     * Only for admin creation
     *
     * @param registerRequest Registration details
     * @param createdBy User ID of admin creating this user
     * @return Created User entity
     */
    @Transactional
    public User createUser(RegisterRequest registerRequest, Long createdBy) {
        log.info("Creating new user by admin: {}", registerRequest.getUsername());

        // Validate username uniqueness
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new IllegalArgumentException("Username already exists");
        }

        // Validate email uniqueness
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new IllegalArgumentException("Email already exists");
        }

        // Validate and set roles
        Set<String> roles = validateAndSetRoles(registerRequest.getRoles());

        // Create user entity
        User user = User.builder()
                .username(registerRequest.getUsername())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .fullName(registerRequest.getFullName())
                .phoneNumber(registerRequest.getPhoneNumber())
                .roles(String.join(",", roles))
                .status("ACTIVE")
                .passwordChangeRequired(true) // Force password change on first login
                .passwordExpiresAt(LocalDateTime.now().plusMonths(3))
                .failedLoginAttempts(0)
                .deleted(false)
                .createdBy(createdBy)
                .build();

        User savedUser = userRepository.save(user);
        log.info("User created successfully by admin: {} with roles: {}", savedUser.getUsername(), roles);

        return savedUser;
    }

    /**
     * Get user by ID
     *
     * @param userId User ID
     * @return User entity
     */
    @Transactional(readOnly = true)
    public User getUserById(Long userId) {
        log.debug("Fetching user by ID: {}", userId);
        return userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with ID: " + userId));
    }

    /**
     * Get user by username
     *
     * @param username Username or email
     * @return User entity
     */
    @Transactional(readOnly = true)
    public User getUserByUsername(String username) {
        log.debug("Fetching user by username: {}", username);
        return userRepository.findByUsernameOrEmail(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
    }

    /**
     * Get all active users
     *
     * @return List of active users
     */
    @Transactional(readOnly = true)
    public List<User> getAllActiveUsers() {
        log.debug("Fetching all active users");
        return userRepository.findAllActiveUsers();
    }

    /**
     * Get users by role
     *
     * @param role Role name
     * @return List of users with specified role
     */
    @Transactional(readOnly = true)
    public List<User> getUsersByRole(String role) {
        log.debug("Fetching users by role: {}", role);
        return userRepository.findByRole(role);
    }

    /**
     * Update user details
     *
     * @param userId User ID
     * @param updateRequest Update details
     * @param updatedBy User ID of user making the update
     * @return Updated User entity
     */
    @Transactional
    public User updateUser(Long userId, RegisterRequest updateRequest, Long updatedBy) {
        log.info("Updating user: {}", userId);

        User user = getUserById(userId);

        // Update username if changed
        if (updateRequest.getUsername() != null &&
                !updateRequest.getUsername().equals(user.getUsername())) {
            if (userRepository.existsByUsername(updateRequest.getUsername())) {
                throw new IllegalArgumentException("Username already exists");
            }
            user.setUsername(updateRequest.getUsername());
        }

        // Update email if changed
        if (updateRequest.getEmail() != null &&
                !updateRequest.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(updateRequest.getEmail())) {
                throw new IllegalArgumentException("Email already exists");
            }
            user.setEmail(updateRequest.getEmail());
        }

        // Update other fields
        if (updateRequest.getFullName() != null) {
            user.setFullName(updateRequest.getFullName());
        }
        if (updateRequest.getPhoneNumber() != null) {
            user.setPhoneNumber(updateRequest.getPhoneNumber());
        }

        // Update password if provided
        if (updateRequest.getPassword() != null && !updateRequest.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(updateRequest.getPassword()));
            user.setPasswordExpiresAt(LocalDateTime.now().plusMonths(3));
        }

        user.setUpdatedBy(updatedBy);
        user.setUpdatedAt(LocalDateTime.now());

        User updatedUser = userRepository.save(user);
        log.info("User updated successfully: {}", userId);

        return updatedUser;
    }

    /**
     * Update user roles
     * Admin only operation
     *
     * @param userId User ID
     * @param roles New roles
     * @param updatedBy User ID of admin making the change
     * @return Updated User entity
     */
    @Transactional
    public User updateUserRoles(Long userId, Set<String> roles, Long updatedBy) {
        log.info("Updating roles for user: {}", userId);

        User user = getUserById(userId);

        // Validate roles
        Set<String> validatedRoles = validateAndSetRoles(roles);

        user.setRoleSet(validatedRoles);
        user.setUpdatedBy(updatedBy);
        user.setUpdatedAt(LocalDateTime.now());

        User updatedUser = userRepository.save(user);
        log.info("User roles updated successfully for user: {} to roles: {}", userId, validatedRoles);

        return updatedUser;
    }

    /**
     * Activate user account
     *
     * @param userId User ID
     * @return Updated User entity
     */
    @Transactional
    public User activateUser(Long userId) {
        log.info("Activating user account: {}", userId);

        User user = getUserById(userId);
        user.setStatus("ACTIVE");
        user.setFailedLoginAttempts(0);
        user.setUpdatedAt(LocalDateTime.now());

        User updatedUser = userRepository.save(user);
        log.info("User account activated: {}", userId);

        return updatedUser;
    }

    /**
     * Deactivate user account
     *
     * @param userId User ID
     * @return Updated User entity
     */
    @Transactional
    public User deactivateUser(Long userId) {
        log.info("Deactivating user account: {}", userId);

        User user = getUserById(userId);
        user.setStatus("INACTIVE");
        user.setUpdatedAt(LocalDateTime.now());

        User updatedUser = userRepository.save(user);
        log.info("User account deactivated: {}", userId);

        return updatedUser;
    }

    /**
     * Lock user account
     *
     * @param userId User ID
     * @return Updated User entity
     */
    @Transactional
    public User lockUser(Long userId) {
        log.info("Locking user account: {}", userId);

        User user = getUserById(userId);
        user.setStatus("LOCKED");
        user.setUpdatedAt(LocalDateTime.now());

        User updatedUser = userRepository.save(user);
        log.info("User account locked: {}", userId);

        return updatedUser;
    }

    /**
     * Unlock user account
     *
     * @param userId User ID
     * @return Updated User entity
     */
    @Transactional
    public User unlockUser(Long userId) {
        log.info("Unlocking user account: {}", userId);

        User user = getUserById(userId);
        user.setStatus("ACTIVE");
        user.setFailedLoginAttempts(0);
        user.setUpdatedAt(LocalDateTime.now());

        User updatedUser = userRepository.save(user);
        log.info("User account unlocked: {}", userId);

        return updatedUser;
    }

    /**
     * Soft delete user
     * Marks user as deleted without removing from database
     *
     * @param userId User ID
     */
    @Transactional
    public void deleteUser(Long userId) {
        log.info("Soft deleting user: {}", userId);

        User user = getUserById(userId);
        user.setDeleted(true);
        user.setStatus("INACTIVE");
        user.setUpdatedAt(LocalDateTime.now());

        userRepository.save(user);
        log.info("User soft deleted: {}", userId);
    }

    /**
     * Permanently delete user
     * Removes user from database (use with caution)
     *
     * @param userId User ID
     */
    @Transactional
    public void permanentlyDeleteUser(Long userId) {
        log.warn("Permanently deleting user: {}", userId);

        userRepository.deleteById(userId);
        log.warn("User permanently deleted: {}", userId);
    }

    /**
     * Search users by term
     * Searches in username, email, and full name
     *
     * @param searchTerm Search term
     * @return List of matching users
     */
    @Transactional(readOnly = true)
    public List<User> searchUsers(String searchTerm) {
        log.debug("Searching users with term: {}", searchTerm);
        return userRepository.searchUsers(searchTerm);
    }

    /**
     * Get user statistics
     * Returns counts of users by status and role
     *
     * @return Map with statistics
     */
    @Transactional(readOnly = true)
    public UserStatistics getUserStatistics() {
        log.debug("Calculating user statistics");

        long totalUsers = userRepository.count();
        long activeUsers = userRepository.countActiveUsers();
        long adminUsers = userRepository.countActiveUsersByRole(Role.ROLE_ADMIN.getRoleName());
        long onboardUsers = userRepository.countActiveUsersByRole(Role.ROLE_ONBOARD.getRoleName());
        long complianceUsers = userRepository.countActiveUsersByRole(Role.ROLE_COMPLIANCE.getRoleName());
        long riskUsers = userRepository.countActiveUsersByRole(Role.ROLE_RISK.getRoleName());
        long approverUsers = userRepository.countActiveUsersByRole(Role.ROLE_APPROVER.getRoleName());

        return UserStatistics.builder()
                .totalUsers(totalUsers)
                .activeUsers(activeUsers)
                .adminUsers(adminUsers)
                .onboardUsers(onboardUsers)
                .complianceUsers(complianceUsers)
                .riskUsers(riskUsers)
                .approverUsers(approverUsers)
                .build();
    }

    /**
     * Map User entity to UserResponse DTO
     *
     * @param user User entity
     * @return UserResponse DTO
     */
    public UserResponse mapToUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .phoneNumber(user.getPhoneNumber())
                .roles(user.getRoleSet())
                .status(user.getStatus())
                .lastLoginAt(user.getLastLoginAt())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .passwordChangeRequired(user.getPasswordChangeRequired())
                .accountExpiresAt(user.getAccountExpiresAt())
                .passwordExpiresAt(user.getPasswordExpiresAt())
                .build();
    }

    /**
     * Map list of Users to list of UserResponse DTOs
     *
     * @param users List of User entities
     * @return List of UserResponse DTOs
     */
    public List<UserResponse> mapToUserResponseList(List<User> users) {
        return users.stream()
                .map(this::mapToUserResponse)
                .collect(Collectors.toList());
    }

    // ==================== PRIVATE HELPER METHODS ====================

    /**
     * Determine roles for new user
     * If no roles specified, assign default role
     *
     * @param requestedRoles Requested roles
     * @return Validated role set
     */
    private Set<String> determineRoles(Set<String> requestedRoles) {
        Set<String> roles = new HashSet<>();

        if (requestedRoles == null || requestedRoles.isEmpty()) {
            // Default role for registration (modify as needed)
            roles.add(Role.ROLE_VIEWER.getRoleName());
            log.debug("No roles specified, assigning default role: ROLE_VIEWER");
        } else {
            roles = validateAndSetRoles(requestedRoles);
        }

        return roles;
    }

    /**
     * Validate and set roles
     * Ensures all roles are valid
     *
     * @param requestedRoles Requested roles
     * @return Validated role set
     */
    private Set<String> validateAndSetRoles(Set<String> requestedRoles) {
        Set<String> validRoles = new HashSet<>();

        for (String role : requestedRoles) {
            // Add ROLE_ prefix if not present
            String normalizedRole = role.startsWith("ROLE_") ? role : "ROLE_" + role;

            // Validate role
            if (Role.isValidRole(normalizedRole)) {
                validRoles.add(normalizedRole);
            } else {
                log.warn("Invalid role requested: {}", role);
                throw new IllegalArgumentException("Invalid role: " + role);
            }
        }

        if (validRoles.isEmpty()) {
            throw new IllegalArgumentException("At least one valid role must be specified");
        }

        return validRoles;
    }

    /**
     * Inner class for user statistics
     */
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class UserStatistics {
        private Long totalUsers;
        private Long activeUsers;
        private Long adminUsers;
        private Long onboardUsers;
        private Long complianceUsers;
        private Long riskUsers;
        private Long approverUsers;
    }
}