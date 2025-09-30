package com.company.backend.config;

import com.company.backend.entity.Role;
import com.company.backend.entity.User;
import com.company.backend.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * DataInitializer - Initializes default data on application startup
 * Creates default admin user and sample users for each role
 *
 * REUSABILITY:
 * This class is reusable across different projects
 * Modify default users and roles as needed
 * Comment out or disable in production after initial setup
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Create default admin user if not exists
        createDefaultAdminUser();

        // Create sample users for each role (development only)
        createSampleUsers();
    }

    /**
     * Create default admin user
     */
    private void createDefaultAdminUser() {
        String adminUsername = "admin";

        if (!userRepository.existsByUsername(adminUsername)) {
            User admin = User.builder()
                    .username(adminUsername)
                    .email("admin@laitusneo.com")
                    .password(passwordEncoder.encode("admin@123"))
                    .fullName("System Admin")
                    .phoneNumber("+1234567890")
                    .roles(Role.ROLE_ADMIN.getRoleName())
                    .status("ACTIVE")
                    .passwordChangeRequired(false)
                    .passwordExpiresAt(LocalDateTime.now().plusYears(1))
                    .failedLoginAttempts(0)
                    .deleted(false)
                    .build();

            userRepository.save(admin);
        }
    }

    /**
     * Create sample users for testing (development only)
     * Remove or comment out in production
     */
    private void createSampleUsers() {
        // Sample Onboarding User
        createUserIfNotExists(
                "onboard_user",
                "onboard@laitusneo.com",
                "Onboard@123",
                "Onboarding Personnel",
                Set.of(Role.ROLE_ONBOARD.getRoleName())
        );

        // Sample Compliance User
        createUserIfNotExists(
                "compliance_user",
                "compliance@laitusneo.com",
                "Compliance@123",
                "Compliance Officer",
                Set.of(Role.ROLE_COMPLIANCE.getRoleName())
        );

        // Sample Risk User
        createUserIfNotExists(
                "risk_user",
                "risk@laitusneo.com",
                "Risk@123",
                "Risk Analyst",
                Set.of(Role.ROLE_RISK.getRoleName())
        );

        // Sample Approver User
        createUserIfNotExists(
                "approver_user",
                "approver@laitusneo.com",
                "Approver@123",
                "Final Approver",
                Set.of(Role.ROLE_APPROVER.getRoleName())
        );

        // Sample Multi-Role User
        createUserIfNotExists(
                "manager_user",
                "manager@laitusneo.com",
                "Manager@123",
                "Manager (Multi-Role)",
                Set.of(
                        Role.ROLE_ONBOARD.getRoleName(),
                        Role.ROLE_COMPLIANCE.getRoleName(),
                        Role.ROLE_RISK.getRoleName()
                )
        );
    }

    /**
     * Create user if not exists
     */
    private void createUserIfNotExists(
            String username,
            String email,
            String password,
            String fullName,
            Set<String> roles) {

        if (!userRepository.existsByUsername(username)) {
            User user = User.builder()
                    .username(username)
                    .email(email)
                    .password(passwordEncoder.encode(password))
                    .fullName(fullName)
                    .phoneNumber("+1234567890")
                    .roles(String.join(",", roles))
                    .status("ACTIVE")
                    .passwordChangeRequired(false)
                    .passwordExpiresAt(LocalDateTime.now().plusMonths(6))
                    .failedLoginAttempts(0)
                    .deleted(false)
                    .build();

            userRepository.save(user);
        }
    }
}
