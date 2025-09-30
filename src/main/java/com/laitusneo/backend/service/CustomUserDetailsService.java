package com.laitusneo.backend.service;

import com.laitusneo.backend.config.CustomUserDetails;
import com.laitusneo.backend.entity.User;
import com.laitusneo.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * CustomUserDetailsService - Implementation of Spring Security's UserDetailsService
 * Loads user-specific data for authentication
 *
 * REUSABILITY:
 * This service is completely reusable across projects
 * Only requirement is having a User entity and UserRepository
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Load user by username for Spring Security authentication
     * This is the core method called during authentication
     *
     * @param username Username or email
     * @return UserDetails object
     * @throws UsernameNotFoundException if user not found
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Loading user by username: {}", username);

        // Try to find user by username or email
        User user = userRepository.findByUsernameOrEmail(username)
                .orElseThrow(() -> {
                    log.warn("User not found with username/email: {}", username);
                    return new UsernameNotFoundException("User not found with username/email: " + username);
                });

        // Check if user is deleted
        if (user.getDeleted()) {
            log.warn("Attempt to login with deleted account: {}", username);
            throw new UsernameNotFoundException("User account has been deleted");
        }

        // Additional security checks can be added here
        if ("INACTIVE".equalsIgnoreCase(user.getStatus())) {
            log.warn("Attempt to login with inactive account: {}", username);
            throw new UsernameNotFoundException("User account is inactive");
        }

        log.debug("User loaded successfully: {} with roles: {}", username, user.getRoles());

        return new CustomUserDetails(user);
    }

    /**
     * Load user by ID
     * Useful for operations that need to reload user details
     *
     * @param userId User ID
     * @return UserDetails object
     * @throws UsernameNotFoundException if user not found
     */
    @Transactional(readOnly = true)
    public UserDetails loadUserById(Long userId) throws UsernameNotFoundException {
        log.debug("Loading user by ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("User not found with ID: {}", userId);
                    return new UsernameNotFoundException("User not found with ID: " + userId);
                });

        if (user.getDeleted()) {
            log.warn("Attempt to access deleted account with ID: {}", userId);
            throw new UsernameNotFoundException("User account has been deleted");
        }

        return new CustomUserDetails(user);
    }

    /**
     * Get User entity by username
     * Returns the actual User entity, not UserDetails
     *
     * @param username Username or email
     * @return User entity
     */
    @Transactional(readOnly = true)
    public User getUserByUsername(String username) {
        log.debug("Fetching user entity for username: {}", username);

        return userRepository.findByUsernameOrEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }

    /**
     * Get User entity by ID
     *
     * @param userId User ID
     * @return User entity
     */
    @Transactional(readOnly = true)
    public User getUserById(Long userId) {
        log.debug("Fetching user entity for ID: {}", userId);

        return userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + userId));
    }

    /**
     * Update last login timestamp
     * Called after successful authentication
     *
     * @param username Username
     */
    @Transactional
    public void updateLastLogin(String username) {
        log.debug("Updating last login time for user: {}", username);

        User user = userRepository.findByUsernameOrEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        user.resetFailedLoginAttempts();
        userRepository.save(user);

        log.info("Last login updated for user: {}", username);
    }

    /**
     * Update last login by user ID
     *
     * @param userId User ID
     */
    @Transactional
    public void updateLastLoginById(Long userId) {
        log.debug("Updating last login time for user ID: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + userId));

        user.resetFailedLoginAttempts();
        userRepository.save(user);

        log.info("Last login updated for user ID: {}", userId);
    }

    /**
     * Increment failed login attempts
     * Called when authentication fails
     *
     * @param username Username
     */
    @Transactional
    public void incrementFailedLoginAttempts(String username) {
        log.debug("Incrementing failed login attempts for user: {}", username);

        userRepository.findByUsernameOrEmail(username).ifPresent(user -> {
            user.incrementFailedLoginAttempts();
            userRepository.save(user);

            if (user.isAccountLocked()) {
                log.warn("User account locked due to failed login attempts: {}", username);
            } else {
                log.info("Failed login attempt #{} for user: {}", user.getFailedLoginAttempts(), username);
            }
        });
    }

    /**
     * Reset failed login attempts
     * Can be called by admin to unlock account
     *
     * @param username Username
     */
    @Transactional
    public void resetFailedLoginAttempts(String username) {
        log.debug("Resetting failed login attempts for user: {}", username);

        User user = userRepository.findByUsernameOrEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        user.setFailedLoginAttempts(0);
        if ("LOCKED".equals(user.getStatus())) {
            user.setStatus("ACTIVE");
        }
        userRepository.save(user);

        log.info("Failed login attempts reset for user: {}", username);
    }

    /**
     * Check if user exists
     *
     * @param username Username or email
     * @return true if user exists
     */
    @Transactional(readOnly = true)
    public boolean userExists(String username) {
        return userRepository.findByUsernameOrEmail(username).isPresent();
    }

    /**
     * Check if user is active
     *
     * @param username Username or email
     * @return true if user is active
     */
    @Transactional(readOnly = true)
    public boolean isUserActive(String username) {
        return userRepository.findByUsernameOrEmail(username)
                .map(User::isAccountActive)
                .orElse(false);
    }

    /**
     * Check if user has specific role
     *
     * @param username Username or email
     * @param role Role to check
     * @return true if user has the role
     */
    @Transactional(readOnly = true)
    public boolean userHasRole(String username, String role) {
        return userRepository.findByUsernameOrEmail(username)
                .map(user -> user.hasRole(role))
                .orElse(false);
    }

    /**
     * Validate user credentials and account status
     * Comprehensive validation before authentication
     *
     * @param username Username or email
     * @return Validation result message
     */
    @Transactional(readOnly = true)
    public String validateUserAccount(String username) {
        User user = userRepository.findByUsernameOrEmail(username)
                .orElse(null);

        if (user == null) {
            return "User not found";
        }

        if (user.getDeleted()) {
            return "Account has been deleted";
        }

        if (user.isAccountLocked()) {
            return "Account is locked due to multiple failed login attempts";
        }

        if (user.isAccountExpired()) {
            return "Account has expired";
        }

        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            return "Account is not active";
        }

        if (user.isPasswordExpired()) {
            return "Password has expired, please reset your password";
        }

        return "VALID"; // Account is valid
    }
}