package com.company.backend.repository;

import com.company.backend.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * UserRepository - Data access layer for User entity
 * Provides reusable queries for user management across any project
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find user by username
     * Primary method for authentication
     */
    Optional<User> findByUsername(String username);

    /**
     * Find user by email
     * Useful for password reset and email-based login
     */
    Optional<User> findByEmail(String email);

    /**
     * Find user by username or email
     * Flexible login method
     */
    @Query("SELECT u FROM User u WHERE u.username = :identifier OR u.email = :identifier")
    Optional<User> findByUsernameOrEmail(@Param("identifier") String identifier);

    /**
     * Check if username exists
     * Useful for registration validation
     */
    boolean existsByUsername(String username);

    /**
     * Check if email exists
     * Useful for registration validation
     */
    boolean existsByEmail(String email);

    /**
     * Find all active users
     * Excludes deleted and inactive accounts
     */
    @Query("SELECT u FROM User u WHERE u.status = 'ACTIVE' AND u.deleted = false")
    List<User> findAllActiveUsers();

    /**
     * Find users by status
     * Example: Find all locked accounts
     */
    List<User> findByStatus(String status);

    /**
     * Find users by role
     * Useful for role-based queries
     * Note: Uses LIKE because roles are stored as comma-separated string
     */
    @Query("SELECT u FROM User u WHERE u.roles LIKE %:role% AND u.deleted = false")
    List<User> findByRole(@Param("role") String role);

    /**
     * Find users with multiple roles
     * Returns users who have ALL specified roles
     */
    @Query("SELECT u FROM User u WHERE " +
            "(:role1 = '' OR u.roles LIKE %:role1%) AND " +
            "(:role2 = '' OR u.roles LIKE %:role2%) AND " +
            "u.deleted = false")
    List<User> findByMultipleRoles(@Param("role1") String role1, @Param("role2") String role2);

    /**
     * Find users created within a date range
     * Useful for reporting
     */
    @Query("SELECT u FROM User u WHERE u.createdAt BETWEEN :startDate AND :endDate AND u.deleted = false")
    List<User> findUsersCreatedBetween(@Param("startDate") LocalDateTime startDate,
                                       @Param("endDate") LocalDateTime endDate);

    /**
     * Find users with failed login attempts greater than threshold
     * Useful for security monitoring
     */
    @Query("SELECT u FROM User u WHERE u.failedLoginAttempts >= :threshold AND u.deleted = false")
    List<User> findUsersWithFailedLoginAttempts(@Param("threshold") Integer threshold);

    /**
     * Find users whose passwords are expiring soon
     * Useful for sending password expiration reminders
     */
    @Query("SELECT u FROM User u WHERE u.passwordExpiresAt IS NOT NULL AND " +
            "u.passwordExpiresAt BETWEEN :now AND :threshold AND u.deleted = false")
    List<User> findUsersWithExpiringPasswords(@Param("now") LocalDateTime now,
                                              @Param("threshold") LocalDateTime threshold);

    /**
     * Find users who haven't logged in for a specific period
     * Useful for identifying inactive accounts
     */
    @Query("SELECT u FROM User u WHERE u.lastLoginAt IS NOT NULL AND " +
            "u.lastLoginAt < :threshold AND u.deleted = false")
    List<User> findInactiveUsersSince(@Param("threshold") LocalDateTime threshold);

    /**
     * Update user's last login timestamp
     * Called on successful authentication
     */
    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :loginTime, u.failedLoginAttempts = 0 " +
            "WHERE u.id = :userId")
    void updateLastLoginTime(@Param("userId") Long userId, @Param("loginTime") LocalDateTime loginTime);

    /**
     * Increment failed login attempts
     */
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 " +
            "WHERE u.id = :userId")
    void incrementFailedLoginAttempts(@Param("userId") Long userId);

    /**
     * Lock user account
     */
    @Modifying
    @Query("UPDATE User u SET u.status = 'LOCKED' WHERE u.id = :userId")
    void lockUserAccount(@Param("userId") Long userId);

    /**
     * Unlock user account
     */
    @Modifying
    @Query("UPDATE User u SET u.status = 'ACTIVE', u.failedLoginAttempts = 0 WHERE u.id = :userId")
    void unlockUserAccount(@Param("userId") Long userId);

    /**
     * Soft delete user
     * Marks user as deleted without actually removing from database
     */
    @Modifying
    @Query("UPDATE User u SET u.deleted = true, u.status = 'INACTIVE' WHERE u.id = :userId")
    void softDeleteUser(@Param("userId") Long userId);

    /**
     * Update user password
     */
    @Modifying
    @Query("UPDATE User u SET u.password = :newPassword, " +
            "u.passwordChangeRequired = false, " +
            "u.passwordExpiresAt = :expiresAt, " +
            "u.updatedAt = :now " +
            "WHERE u.id = :userId")
    void updatePassword(@Param("userId") Long userId,
                        @Param("newPassword") String newPassword,
                        @Param("expiresAt") LocalDateTime expiresAt,
                        @Param("now") LocalDateTime now);

    /**
     * Count active users by role
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.roles LIKE %:role% AND " +
            "u.status = 'ACTIVE' AND u.deleted = false")
    Long countActiveUsersByRole(@Param("role") String role);

    /**
     * Count total active users
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.status = 'ACTIVE' AND u.deleted = false")
    Long countActiveUsers();

    /**
     * Find users by search term (username, email, or full name)
     * Useful for admin user search functionality
     */
    @Query("SELECT u FROM User u WHERE " +
            "(LOWER(u.username) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.fullName) LIKE LOWER(CONCAT('%', :searchTerm, '%'))) AND " +
            "u.deleted = false")
    List<User> searchUsers(@Param("searchTerm") String searchTerm);

    /**
     * Find users created by a specific user
     * Useful for audit and hierarchy
     */
    List<User> findByCreatedByAndDeletedFalse(Long createdBy);

    /**
     * Check if user has specific role
     */
    @Query("SELECT CASE WHEN COUNT(u) > 0 THEN true ELSE false END FROM User u " +
            "WHERE u.id = :userId AND u.roles LIKE %:role%")
    boolean userHasRole(@Param("userId") Long userId, @Param("role") String role);
}