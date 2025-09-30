package com.company.backend.config;

import com.company.backend.entity.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * CustomUserDetails - Implementation of Spring Security's UserDetails
 * Wraps our User entity to work with Spring Security
 *
 * REUSABILITY:
 * This class adapts your User entity to Spring Security
 * Can be reused in any project with minimal modifications
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Data
@AllArgsConstructor
public class CustomUserDetails implements UserDetails {

    private Long id;
    private String username;
    private String password;
    private String email;
    private String fullName;
    private Set<String> roles;
    private String status;
    private Boolean accountExpired;
    private Boolean accountLocked;
    private Boolean credentialsExpired;
    private Boolean enabled;

    /**
     * Constructor from User entity
     * Converts User entity to CustomUserDetails
     *
     * @param user User entity
     */
    public CustomUserDetails(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.email = user.getEmail();
        this.fullName = user.getFullName();
        this.roles = user.getRoleSet();
        this.status = user.getStatus();

        // Account status checks
        this.accountExpired = user.isAccountExpired();
        this.accountLocked = user.isAccountLocked();
        this.credentialsExpired = user.isPasswordExpired();
        this.enabled = user.isAccountActive();
    }

    /**
     * Get authorities (roles) for Spring Security
     * Converts role strings to GrantedAuthority objects
     *
     * @return Collection of granted authorities
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    /**
     * Check if account is not expired
     *
     * @return true if account is valid
     */
    @Override
    public boolean isAccountNonExpired() {
        return !accountExpired;
    }

    /**
     * Check if account is not locked
     *
     * @return true if account is not locked
     */
    @Override
    public boolean isAccountNonLocked() {
        return !accountLocked;
    }

    /**
     * Check if credentials (password) are not expired
     *
     * @return true if credentials are valid
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return !credentialsExpired;
    }

    /**
     * Check if account is enabled
     *
     * @return true if account is enabled
     */
    @Override
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Check if user has a specific role
     *
     * @param role Role to check
     * @return true if user has the role
     */
    public boolean hasRole(String role) {
        return roles.contains(role);
    }

    /**
     * Check if user has any of the specified roles
     *
     * @param rolesToCheck Roles to check
     * @return true if user has any of the roles
     */
    public boolean hasAnyRole(String... rolesToCheck) {
        for (String role : rolesToCheck) {
            if (roles.contains(role)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if user has all of the specified roles
     *
     * @param rolesToCheck Roles to check
     * @return true if user has all of the roles
     */
    public boolean hasAllRoles(String... rolesToCheck) {
        for (String role : rolesToCheck) {
            if (!roles.contains(role)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get user ID
     * Useful for audit logging and queries
     *
     * @return User ID
     */
    public Long getId() {
        return id;
    }

    /**
     * Get user's email
     *
     * @return Email address
     */
    public String getEmail() {
        return email;
    }

    /**
     * Get user's full name
     *
     * @return Full name
     */
    public String getFullName() {
        return fullName;
    }

    /**
     * Get user's roles as Set
     *
     * @return Set of role strings
     */
    public Set<String> getRoles() {
        return roles;
    }

    /**
     * Get user's status
     *
     * @return Status string (ACTIVE, LOCKED, etc.)
     */
    public String getStatus() {
        return status;
    }
}