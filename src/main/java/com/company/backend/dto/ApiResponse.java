package com.company.backend.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * ApiResponse DTO - Generic response wrapper for API responses
 *
 * REUSABILITY:
 * This DTO is completely reusable across different projects
 * Provides consistent response format
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {

    /**
     * Success flag
     */
    private Boolean success;

    /**
     * Response message
     */
    private String message;

    /**
     * Response data (generic type)
     */
    private T data;

    /**
     * Error details (if any)
     */
    private String error;

    /**
     * Timestamp
     */
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();

    /**
     * HTTP status code
     */
    private Integer status;

    /**
     * Request path
     */
    private String path;

    // ==================== FACTORY METHODS ====================

    /**
     * Create success response with data
     */
    public static <T> ApiResponse<T> success(T data) {
        return ApiResponse.<T>builder()
                .success(true)
                .data(data)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Create success response with message and data
     */
    public static <T> ApiResponse<T> success(String message, T data) {
        return ApiResponse.<T>builder()
                .success(true)
                .message(message)
                .data(data)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Create success response with only message
     */
    public static <T> ApiResponse<T> success(String message) {
        return ApiResponse.<T>builder()
                .success(true)
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Create error response with message
     */
    public static <T> ApiResponse<T> error(String message) {
        return ApiResponse.<T>builder()
                .success(false)
                .message(message)
                .error(message)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Create error response with message and error details
     */
    public static <T> ApiResponse<T> error(String message, String error) {
        return ApiResponse.<T>builder()
                .success(false)
                .message(message)
                .error(error)
                .timestamp(LocalDateTime.now())
                .build();
    }

    /**
     * Create error response with status code
     */
    public static <T> ApiResponse<T> error(String message, Integer status) {
        return ApiResponse.<T>builder()
                .success(false)
                .message(message)
                .error(message)
                .status(status)
                .timestamp(LocalDateTime.now())
                .build();
    }
}