package com.company.backend.service;

import com.company.backend.config.CustomUserDetails;
import com.company.backend.entity.User;
import com.company.backend.repository.UserRepository;
import com.company.backend.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * AuthService - Handles authentication and authorization operations
 * Central service for login, token generation, and user validation
 *
 * REUSABILITY:
 * This service is completely reusable across different projects
 * It handles all JWT-based authentication logic
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    /**
     * Authenticate user and generate JWT tokens
     * Main login method
     *
     * @param username Username or email
     * @param password Password
     * @return Map containing access token, refresh token, and user info
     */
    @Transactional
    public Map<String, Object> login(String username, String password) {
        log.info("Login attempt for user: {}", username);

        try {
            // Validate account status before authentication
            String validationResult = userDetailsService.validateUserAccount(username);
            if (!"VALID".equals(validationResult)) {
                log.warn("Login failed for user {}: {}", username, validationResult);
                throw new BadCredentialsException(validationResult);
            }

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            // Get user details
            CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
            User user = userDetailsService.getUserById(userDetails.getId());

            // Update last login
            userDetailsService.updateLastLoginById(user.getId());

            // Generate tokens
            String accessToken = jwtUtil.generateToken(
                    user.getUsername(),
                    user.getId(),
                    user.getRoleSet()
            );

            String refreshToken = jwtUtil.generateRefreshToken(
                    user.getUsername(),
                    user.getId()
            );

            // Prepare response
            Map<String, Object> response = new HashMap<>();
            response.put("accessToken", accessToken);
            response.put("refreshToken", refreshToken);
            response.put("tokenType", "Bearer");
            response.put("expiresIn", jwtUtil.getRemainingTimeInSeconds(accessToken));
            response.put("user", buildUserInfo(user));

            log.info("Login successful for user: {}", username);
            return response;

        } catch (DisabledException e) {
            log.warn("Account disabled for user: {}", username);
            userDetailsService.incrementFailedLoginAttempts(username);
            throw new BadCredentialsException("Account is disabled");
        } catch (LockedException e) {
            log.warn("Account locked for user: {}", username);
            throw new BadCredentialsException("Account is locked due to multiple failed login attempts");
        } catch (BadCredentialsException e) {
            log.warn("Invalid credentials for user: {}", username);
            userDetailsService.incrementFailedLoginAttempts(username);
            throw new BadCredentialsException("Invalid username or password");
        } catch (Exception e) {
            log.error("Login error for user {}: {}", username, e.getMessage(), e);
            throw new RuntimeException("Authentication failed: " + e.getMessage());
        }
    }

    /**
     * Refresh access token using refresh token
     *
     * @param refreshToken Refresh token
     * @return Map containing new access token and expiration
     */
    @Transactional(readOnly = true)
    public Map<String, Object> refreshToken(String refreshToken) {
        log.debug("Token refresh request");

        try {
            // Validate refresh token
            if (!jwtUtil.validateToken(refreshToken)) {
                log.warn("Invalid refresh token");
                throw new BadCredentialsException("Invalid refresh token");
            }

            if (!jwtUtil.isRefreshToken(refreshToken)) {
                log.warn("Token is not a refresh token");
                throw new BadCredentialsException("Provided token is not a refresh token");
            }

            // Extract user info
            String username = jwtUtil.extractUsername(refreshToken);
            Long userId = jwtUtil.extractUserId(refreshToken);

            // Get user and validate
            User user = userDetailsService.getUserById(userId);

            if (!user.getUsername().equals(username)) {
                log.warn("Token username mismatch for user ID: {}", userId);
                throw new BadCredentialsException("Invalid token");
            }

            if (!user.isAccountActive()) {
                log.warn("Account not active for user: {}", username);
                throw new BadCredentialsException("Account is not active");
            }

            // Generate new access token
            String newAccessToken = jwtUtil.generateToken(
                    user.getUsername(),
                    user.getId(),
                    user.getRoleSet()
            );

            Map<String, Object> response = new HashMap<>();
            response.put("accessToken", newAccessToken);
            response.put("tokenType", "Bearer");
            response.put("expiresIn", jwtUtil.getRemainingTimeInSeconds(newAccessToken));

            log.info("Token refreshed successfully for user: {}", username);
            return response;

        } catch (Exception e) {
            log.error("Token refresh error: {}", e.getMessage());
            throw new BadCredentialsException("Token refresh failed: " + e.getMessage());
        }
    }

    /**
     * Validate token and return user details
     *
     * @param token JWT token
     * @return Map containing user details
     */
    @Transactional(readOnly = true)
    public Map<String, Object> validateToken(String token) {
        log.debug("Token validation request");

        try {
            if (!jwtUtil.validateToken(token)) {
                throw new BadCredentialsException("Invalid token");
            }

            String username = jwtUtil.extractUsername(token);
            Long userId = jwtUtil.extractUserId(token);
            Set<String> roles = jwtUtil.extractRolesAsSet(token);

            User user = userDetailsService.getUserById(userId);

            Map<String, Object> response = new HashMap<>();
            response.put("valid", true);
            response.put("username", username);
            response.put("userId", userId);
            response.put("roles", roles);
            response.put("expiresIn", jwtUtil.getRemainingTimeInSeconds(token));
            response.put("user", buildUserInfo(user));

            log.debug("Token validated successfully for user: {}", username);
            return response;

        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
            Map<String, Object> response = new HashMap<>();
            response.put("valid", false);
            response.put("message", e.getMessage());
            return response;
        }
    }

    /**
     * Change user password
     *
     * @param userId User ID
     * @param oldPassword Current password
     * @param newPassword New password
     */
    @Transactional
    public void changePassword(Long userId, String oldPassword, String newPassword) {
        log.info("Password change request for user ID: {}", userId);

        User user = userDetailsService.getUserById(userId);

        // Verify old password
        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            log.warn("Invalid old password for user ID: {}", userId);
            throw new BadCredentialsException("Current password is incorrect");
        }

        // Validate new password
        validatePassword(newPassword);

        // Update password
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordChangeRequired(false);
        user.setPasswordExpiresAt(LocalDateTime.now().plusMonths(3)); // 3 months validity
        user.setUpdatedAt(LocalDateTime.now());
        user.setUpdatedBy(userId);

        userRepository.save(user);

        log.info("Password changed successfully for user ID: {}", userId);
    }

    /**
     * Reset password (admin function or forgot password)
     *
     * @param username Username or email
     * @param newPassword New password
     */
    @Transactional
    public void resetPassword(String username, String newPassword) {
        log.info("Password reset request for user: {}", username);

        User user = userDetailsService.getUserByUsername(username);

        // Validate new password
        validatePassword(newPassword);

        // Update password
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordChangeRequired(true); // Force change on next login
        user.setPasswordExpiresAt(LocalDateTime.now().plusMonths(3));
        user.setFailedLoginAttempts(0);
        user.setStatus("ACTIVE"); // Unlock if locked

        userRepository.save(user);

        log.info("Password reset successfully for user: {}", username);
    }

    /**
     * Logout user (invalidate token on client side)
     * In JWT, actual logout is handled client-side by removing token
     * This method can be used for audit logging
     *
     * @param token JWT token
     */
    public void logout(String token) {
        try {
            String username = jwtUtil.extractUsername(token);
            log.info("Logout request for user: {}", username);

            // Here you can add token blacklisting logic if needed
            // For now, just log the logout

            log.info("User logged out: {}", username);
        } catch (Exception e) {
            log.warn("Logout error: {}", e.getMessage());
        }
    }

    /**
     * Check if user has specific role
     *
     * @param userId User ID
     * @param role Role to check
     * @return true if user has the role
     */
    @Transactional(readOnly = true)
    public boolean hasRole(Long userId, String role) {
        User user = userDetailsService.getUserById(userId);
        return user.hasRole(role);
    }

    /**
     * Check if user has any of the specified roles
     *
     * @param userId User ID
     * @param roles Roles to check
     * @return true if user has any of the roles
     */
    @Transactional(readOnly = true)
    public boolean hasAnyRole(Long userId, String... roles) {
        User user = userDetailsService.getUserById(userId);
        Set<String> userRoles = user.getRoleSet();

        for (String role : roles) {
            if (userRoles.contains(role)) {
                return true;
            }
        }
        return false;
    }

    // ==================== PRIVATE HELPER METHODS ====================

    /**
     * Build user info map for response
     */
    private Map<String, Object> buildUserInfo(User user) {
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("id", user.getId());
        userInfo.put("username", user.getUsername());
        userInfo.put("email", user.getEmail());
        userInfo.put("fullName", user.getFullName());
        userInfo.put("roles", user.getRoleSet());
        userInfo.put("status", user.getStatus());
        userInfo.put("lastLoginAt", user.getLastLoginAt());
        return userInfo;
    }

    /**
     * Validate password strength
     */
    private void validatePassword(String password) {
        if (password == null || password.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters long");
        }

        // Add more password validation rules as needed
        boolean hasUpperCase = password.chars().anyMatch(Character::isUpperCase);
        boolean hasLowerCase = password.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(ch -> "!@#$%^&*()_+-=[]{}|;:,.<>?".indexOf(ch) >= 0);

        if (!hasUpperCase || !hasLowerCase || !hasDigit || !hasSpecial) {
            throw new IllegalArgumentException(
                    "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character"
            );
        }
    }
}