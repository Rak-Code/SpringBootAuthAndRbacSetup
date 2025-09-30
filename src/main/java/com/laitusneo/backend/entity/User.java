package com.laitusneo.backend.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * User Entity - Represents system users with authentication and authorization details
 * This entity is designed to be reusable across different projects by simply modifying roles
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Entity
@Table(name = "users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "username"),
                @UniqueConstraint(columnNames = "email")
        },
        indexes = {
                @Index(name = "idx_username", columnList = "username"),
                @Index(name = "idx_email", columnList = "email"),
                @Index(name = "idx_status", columnList = "status")
        })
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(nullable = false)
    private String password; // BCrypt hashed password

    @Column(nullable = false, unique = true, length = 100)
    private String email;

    @Column(length = 100)
    private String fullName;

    @Column(length = 15)
    private String phoneNumber;

    /**
     * User roles stored as comma-separated values
     * Example: "ROLE_ADMIN,ROLE_ONBOARD" or single role "ROLE_COMPLIANCE"
     * This approach allows flexible role management
     */
    @Column(nullable = false, length = 255)
    private String roles; // Stored as comma-separated: "ROLE_ADMIN,ROLE_ONBOARD"

    /**
     * Account status: ACTIVE, INACTIVE, LOCKED, EXPIRED
     * Allows for account lifecycle management
     */
    @Column(nullable = false, length = 20)
    @Builder.Default
    private String status = "ACTIVE";

    /**
     * Flag to force password change on next login
     * Useful for security policies
     */
    @Column(nullable = false)
    @Builder.Default
    private Boolean passwordChangeRequired = false;

    /**
     * Failed login attempt counter for security
     * Can be used to implement account locking mechanism
     */
    @Column(nullable = false)
    @Builder.Default
    private Integer failedLoginAttempts = 0;

    /**
     * Timestamp of last successful login
     */
    @Column
    private LocalDateTime lastLoginAt;

    /**
     * Account expiration date (optional)
     * Null means no expiration
     */
    @Column
    private LocalDateTime accountExpiresAt;

    /**
     * Password expiration date (optional)
     * Useful for enforcing password rotation policies
     */
    @Column
    private LocalDateTime passwordExpiresAt;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @Column
    private Long createdBy; // User ID who created this account

    @Column
    private Long updatedBy; // User ID who last updated this account

    /**
     * Soft delete flag
     * Allows keeping user data for audit purposes while marking as deleted
     */
    @Column(nullable = false)
    @Builder.Default
    private Boolean deleted = false;

    /**
     * Additional metadata in JSON format (optional)
     * Can store any additional user-specific information
     */
    @Column(columnDefinition = "TEXT")
    private String metadata;

    // ==================== Utility Methods ====================

    /**
     * Parse roles string into a Set
     * Reusable method for role checking
     */
    public Set<String> getRoleSet() {
        Set<String> roleSet = new HashSet<>();
        if (roles != null && !roles.trim().isEmpty()) {
            String[] roleArray = roles.split(",");
            for (String role : roleArray) {
                roleSet.add(role.trim());
            }
        }
        return roleSet;
    }

    /**
     * Check if user has a specific role
     */
    public boolean hasRole(String role) {
        return getRoleSet().contains(role);
    }

    /**
     * Check if user account is active and not locked
     */
    public boolean isAccountActive() {
        return "ACTIVE".equalsIgnoreCase(status) && !deleted;
    }

    /**
     * Check if account is locked due to failed login attempts
     */
    public boolean isAccountLocked() {
        return "LOCKED".equalsIgnoreCase(status);
    }

    /**
     * Check if account has expired
     */
    public boolean isAccountExpired() {
        if (accountExpiresAt == null) {
            return false;
        }
        return LocalDateTime.now().isAfter(accountExpiresAt);
    }

    /**
     * Check if password has expired
     */
    public boolean isPasswordExpired() {
        if (passwordExpiresAt == null) {
            return false;
        }
        return LocalDateTime.now().isAfter(passwordExpiresAt);
    }

    /**
     * Increment failed login attempts
     */
    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts++;
        // Auto-lock account after 5 failed attempts
        if (this.failedLoginAttempts >= 5) {
            this.status = "LOCKED";
        }
    }

    /**
     * Reset failed login attempts on successful login
     */
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
        this.lastLoginAt = LocalDateTime.now();
    }

    /**
     * Add a role to existing roles
     */
    public void addRole(String role) {
        Set<String> roleSet = getRoleSet();
        roleSet.add(role);
        this.roles = String.join(",", roleSet);
    }

    /**
     * Remove a role from existing roles
     */
    public void removeRole(String role) {
        Set<String> roleSet = getRoleSet();
        roleSet.remove(role);
        this.roles = String.join(",", roleSet);
    }

    /**
     * Set multiple roles at once
     */
    public void setRoleSet(Set<String> roleSet) {
        this.roles = String.join(",", roleSet);
    }
}