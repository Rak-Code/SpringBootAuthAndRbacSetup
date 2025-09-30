package com.laitusneo.backend.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * JwtAuthenticationEntryPoint - Handles authentication errors
 * Returns JSON error response when authentication fails
 *
 * REUSABILITY:
 * This class is completely reusable across different projects
 * Provides consistent error responses for authentication failures
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Handle authentication error
     * Called when user tries to access a secured REST resource without authentication
     *
     * @param request HTTP request
     * @param response HTTP response
     * @param authException Authentication exception
     * @throws IOException if IO error occurs
     * @throws ServletException if servlet error occurs
     */
    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException, ServletException {

        log.error("Unauthorized access attempt to: {} - {}",
                request.getRequestURI(),
                authException.getMessage());

        // Set response status to 401 Unauthorized
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        // Build error response
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now().toString());
        errorResponse.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        errorResponse.put("error", "Unauthorized");
        errorResponse.put("message", authException.getMessage());
        errorResponse.put("path", request.getRequestURI());

        // Additional details for debugging (remove in production)
        if (log.isDebugEnabled()) {
            errorResponse.put("exception", authException.getClass().getName());
        }

        // Write JSON response
        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}