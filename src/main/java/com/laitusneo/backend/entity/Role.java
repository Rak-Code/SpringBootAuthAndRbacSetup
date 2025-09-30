package com.laitusneo.backend.entity;

/**
 * Role Enum - Defines all available roles in the system
 * This enum makes role management type-safe and easier to refactor
 *
 * HOW TO REUSE IN DIFFERENT PROJECTS:
 * Simply modify the enum values to match your project's roles
 * Example: For an e-commerce system, you might have:
 * ROLE_CUSTOMER, ROLE_SELLER, ROLE_ADMIN, ROLE_SUPPORT
 *
 * @author Senior Java Developer
 * @version 1.0
 */
public enum Role {

    /**
     * Administrator role - Full system access
     * Can manage users, view all data, configure system settings
     */
    ROLE_ADMIN("ROLE_ADMIN", "Administrator", "Full system access with all privileges"),

    /**
     * Onboarding Personnel role
     * Can create and submit merchant applications
     */
    ROLE_ONBOARD("ROLE_ONBOARD", "Onboarding Personnel", "Create and submit merchant applications"),

    /**
     * Compliance Team role
     * Can review applications for compliance requirements
     */
    ROLE_COMPLIANCE("ROLE_COMPLIANCE", "Compliance Officer", "Review applications for compliance"),

    /**
     * Risk Assessment Team role
     * Can assess risk levels of applications
     */
    ROLE_RISK("ROLE_RISK", "Risk Analyst", "Assess risk levels of applications"),

    /**
     * Final Approver role
     * Can make final approval/rejection decisions
     */
    ROLE_APPROVER("ROLE_APPROVER", "Final Approver", "Make final approval decisions"),

    /**
     * Read-only user role (optional)
     * Can view data but not modify
     */
    ROLE_VIEWER("ROLE_VIEWER", "Viewer", "Read-only access to applications");

    private final String roleName;
    private final String displayName;
    private final String description;

    Role(String roleName, String displayName, String description) {
        this.roleName = roleName;
        this.displayName = displayName;
        this.description = description;
    }

    public String getRoleName() {
        return roleName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Get Role enum from string role name
     * Useful for converting string roles to enum
     */
    public static Role fromString(String roleName) {
        for (Role role : Role.values()) {
            if (role.getRoleName().equalsIgnoreCase(roleName)) {
                return role;
            }
        }
        throw new IllegalArgumentException("No role found with name: " + roleName);
    }

    /**
     * Check if a role name is valid
     */
    public static boolean isValidRole(String roleName) {
        try {
            fromString(roleName);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Get all role names as a comma-separated string
     */
    public static String getAllRoleNames() {
        StringBuilder sb = new StringBuilder();
        for (Role role : Role.values()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(role.getRoleName());
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return this.roleName;
    }
}