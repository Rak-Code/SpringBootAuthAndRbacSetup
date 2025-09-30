package com.company.backend.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * SecurityConfig - Main Spring Security configuration
 * Configures authentication, authorization, JWT filter, and security policies
 *
 * REUSABILITY:
 * This configuration is highly reusable across projects
 * Modify the authorization rules in securityFilterChain() to match your project's needs
 * Update Role references if using different role names
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    /**
     * Configure security filter chain
     * Defines authorization rules, session management, and filters
     *
     * @param http HttpSecurity object
     * @return SecurityFilterChain
     * @throws Exception if configuration error occurs
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CSRF (not needed for stateless JWT authentication)
                .csrf(AbstractHttpConfigurer::disable)

                // Configure CORS
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                // Configure authorization rules
                .authorizeHttpRequests(auth -> auth
                        // ==================== PUBLIC ENDPOINTS ====================
                        // Allow access without authentication
                        .requestMatchers(
                                "/api/auth/login",
                                "/api/auth/register",
                                "/api/auth/refresh",
                                "/api/public/**"
                        ).permitAll()

                        // ==================== SWAGGER/API DOCS ====================
                        // Allow Swagger UI and API documentation
                        .requestMatchers(
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**",
                                "/v3/api-docs",
                                "/swagger-resources/**",
                                "/webjars/**",
                                "/swagger-ui/index.html",
                                "/swagger-ui/index.html/**"
                        ).permitAll()

                        // ==================== ADMIN ENDPOINTS ====================
                        // Only ROLE_ADMIN can access
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/users/**").hasRole("ADMIN")

                        // ==================== ONBOARDING ENDPOINTS ====================
                        // ROLE_ONBOARD can access
                        .requestMatchers(HttpMethod.POST, "/api/applications").hasAnyRole("ONBOARD", "ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/api/applications/**").hasAnyRole("ONBOARD", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/applications/*/documents").hasAnyRole("ONBOARD", "ADMIN")
                        .requestMatchers(HttpMethod.POST, "/api/applications/*/submit").hasAnyRole("ONBOARD", "ADMIN")

                        // ==================== COMPLIANCE ENDPOINTS ====================
                        // ROLE_COMPLIANCE can access
                        .requestMatchers("/api/compliance/**").hasAnyRole("COMPLIANCE", "ADMIN")

                        // ==================== RISK ENDPOINTS ====================
                        // ROLE_RISK can access
                        .requestMatchers("/api/risk/**").hasAnyRole("RISK", "ADMIN")

                        // ==================== APPROVAL ENDPOINTS ====================
                        // ROLE_APPROVER can access
                        .requestMatchers("/api/approval/**").hasAnyRole("APPROVER", "ADMIN")

                        // ==================== DASHBOARD ENDPOINTS ====================
                        // All authenticated users can access dashboard
                        .requestMatchers("/api/dashboard/**").authenticated()

                        // ==================== APPLICATION VIEW ====================
                        // All authenticated users can view applications
                        .requestMatchers(HttpMethod.GET, "/api/applications/**").authenticated()

                        // ==================== DEFAULT ====================
                        // All other requests require authentication
                        .anyRequest().authenticated()
                )

                // Configure exception handling
                .exceptionHandling(exception -> exception
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                )

                // Configure session management (stateless for JWT)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Configure authentication provider
                .authenticationProvider(authenticationProvider())

                // Add JWT filter before UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Configure CORS
     * Uses patterns instead of specific origins for better flexibility
     * Allows requests from any origin (configure for production)
     *
     * @return CorsConfigurationSource
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Use patterns instead of origins for development flexibility
        // In production, replace with specific domain patterns
        configuration.setAllowedOriginPatterns(List.of("*"));

        // Allow all HTTP methods
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
        ));

        // Allow all headers
        configuration.setAllowedHeaders(List.of("*"));

        // Allow credentials (cookies, authorization headers)
        configuration.setAllowCredentials(true);

        // Expose headers to client
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Total-Count",
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials"
        ));

        // Max age for preflight requests
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    /**
     * Configure authentication provider
     * Uses DaoAuthenticationProvider with UserDetailsService and PasswordEncoder
     *
     * @return AuthenticationProvider
     */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(passwordEncoder());
        authProvider.setUserDetailsService(userDetailsService);
        return authProvider;
    }

    /**
     * Configure authentication manager
     * Required for manual authentication (e.g., in login controller)
     *
     * @param config AuthenticationConfiguration
     * @return AuthenticationManager
     * @throws Exception if configuration error occurs
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * Configure password encoder
     * Uses BCrypt for password hashing
     *
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt with strength 12 (default is 10)
        // Higher strength = more secure but slower
        return new BCryptPasswordEncoder(12);
    }
}