package com.laitusneo.backend.config;

import com.laitusneo.backend.service.CustomUserDetailsService;
import com.laitusneo.backend.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JwtAuthenticationFilter - Intercepts all HTTP requests and validates JWT tokens
 * This filter runs once per request and extracts/validates JWT from Authorization header
 *
 * REUSABILITY:
 * This filter is completely reusable across different projects
 * No project-specific logic - works with any JWT-based authentication
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;

    // Authorization header name
    private static final String AUTHORIZATION_HEADER = "Authorization";

    // Token prefix (Bearer)
    private static final String TOKEN_PREFIX = "Bearer ";

    // Length of "Bearer " prefix
    private static final int TOKEN_PREFIX_LENGTH = 7;

    /**
     * Main filter method - processes each HTTP request
     * Extracts JWT token, validates it, and sets authentication in SecurityContext
     *
     * @param request HTTP request
     * @param response HTTP response
     * @param filterChain Filter chain
     * @throws ServletException if servlet error occurs
     * @throws IOException if IO error occurs
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            // Extract JWT token from request
            String jwt = extractJwtFromRequest(request);

            // If no token found, continue without authentication
            if (jwt == null) {
                log.trace("No JWT token found in request to: {}", request.getRequestURI());
                filterChain.doFilter(request, response);
                return;
            }

            // Validate and process token
            processJwtToken(jwt, request);

        } catch (Exception e) {
            // Log error but continue filter chain
            // Authentication will fail if token is invalid
            log.error("Cannot set user authentication: {}", e.getMessage());

            // Clear security context on error
            SecurityContextHolder.clearContext();
        }

        // Continue filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWT token from Authorization header
     * Expects format: "Bearer <token>"
     *
     * @param request HTTP request
     * @return JWT token string or null if not found
     */
    private String extractJwtFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader(AUTHORIZATION_HEADER);

        // Check if Authorization header exists and starts with "Bearer "
        if (authorizationHeader != null && authorizationHeader.startsWith(TOKEN_PREFIX)) {
            String token = authorizationHeader.substring(TOKEN_PREFIX_LENGTH);
            log.trace("JWT token extracted from request");
            return token;
        }

        return null;
    }

    /**
     * Process JWT token - validate and set authentication
     *
     * @param jwt JWT token string
     * @param request HTTP request
     */
    private void processJwtToken(String jwt, HttpServletRequest request) {
        try {
            // Extract username from token
            String username = jwtUtil.extractUsername(jwt);

            log.debug("Processing JWT for user: {}", username);

            // Check if user is not already authenticated
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // Load user details
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // Validate token against user details
                if (jwtUtil.validateToken(jwt, userDetails)) {

                    // Create authentication token
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    // Set additional details from request
                    authenticationToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    // Set authentication in SecurityContext
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    log.debug("User authenticated successfully: {} with roles: {}",
                            username, userDetails.getAuthorities());

                    // Log token expiration info (trace level)
                    if (log.isTraceEnabled()) {
                        Long remainingSeconds = jwtUtil.getRemainingTimeInSeconds(jwt);
                        log.trace("Token expires in {} seconds", remainingSeconds);
                    }
                } else {
                    log.warn("JWT token validation failed for user: {}", username);
                }
            }
        } catch (Exception e) {
            log.error("Error processing JWT token: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Determine if filter should be applied to this request
     * Can be overridden to skip certain paths
     *
     * @param request HTTP request
     * @return true if filter should not be applied
     */
    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI();

        // Skip filter for public endpoints
        // These paths don't require authentication
        return path.startsWith("/api/auth/login") ||
                path.startsWith("/api/auth/register") ||
                path.startsWith("/api/auth/refresh") ||
                path.startsWith("/api/public/") ||
                path.startsWith("/swagger-ui") ||
                path.startsWith("/swagger-ui.html") ||
                path.startsWith("/v3/api-docs") ||
                path.startsWith("/swagger-resources") ||
                path.startsWith("/webjars/") ||
                path.equals("/favicon.ico") ||
                path.equals("/error") ||
                path.equals("/") ||
                path.startsWith("/actuator/");
    }
}