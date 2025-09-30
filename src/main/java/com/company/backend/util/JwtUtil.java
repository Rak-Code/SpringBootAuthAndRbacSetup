package com.company.backend.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * JwtUtil - Utility class for JWT token operations
 * Handles token generation, validation, and extraction of claims
 *
 * REUSABILITY NOTES:
 * - Configure jwt.secret and jwt.expiration in application.properties
 * - Works with any UserDetails implementation
 * - Can be used across different projects without modification
 *
 * @author Senior Java Developer
 * @version 1.0
 */
@Component
public class JwtUtil {

    // JWT Secret key from application.properties
    // IMPORTANT: Use a strong secret key (at least 256 bits for HS256)
    @Value("${jwt.secret}")
    private String SECRET_KEY;

    // Token expiration time in milliseconds (default: 24 hours)
    @Value("${jwt.expiration:86400000}")
    private Long JWT_TOKEN_VALIDITY;

    // Refresh token expiration (default: 7 days)
    @Value("${jwt.refresh.expiration:604800000}")
    private Long JWT_REFRESH_TOKEN_VALIDITY;

    /**
     * Generate SecretKey from the configured secret string
     * Uses HMAC-SHA256 algorithm
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // ==================== TOKEN GENERATION ====================

    /**
     * Generate JWT token for user with roles
     * This is the main method for token generation
     *
     * @param username User's username
     * @param userId User's ID
     * @param roles User's roles as Set<String>
     * @return JWT token string
     */
    public String generateToken(String username, Long userId, Set<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("roles", String.join(",", roles));
        claims.put("tokenType", "ACCESS");
        return createToken(claims, username, JWT_TOKEN_VALIDITY);
    }

    /**
     * Generate JWT token with custom claims
     * Flexible method for any additional data
     *
     * @param username User's username
     * @param additionalClaims Any additional claims to include
     * @return JWT token string
     */
    public String generateTokenWithClaims(String username, Map<String, Object> additionalClaims) {
        return createToken(additionalClaims, username, JWT_TOKEN_VALIDITY);
    }

    /**
     * Generate refresh token
     * Refresh tokens have longer expiration and limited claims
     *
     * @param username User's username
     * @param userId User's ID
     * @return Refresh token string
     */
    public String generateRefreshToken(String username, Long userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("tokenType", "REFRESH");
        return createToken(claims, username, JWT_REFRESH_TOKEN_VALIDITY);
    }

    /**
     * Core method to create JWT token
     *
     * @param claims Additional claims to include
     * @param subject Username (subject of the token)
     * @param validity Token validity duration in milliseconds
     * @return JWT token string
     */
    private String createToken(Map<String, Object> claims, String subject, Long validity) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + validity);

        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    // ==================== TOKEN VALIDATION ====================

    /**
     * Validate JWT token against UserDetails
     * Checks if token is valid and belongs to the user
     *
     * @param token JWT token
     * @param userDetails Spring Security UserDetails
     * @return true if valid, false otherwise
     */
    public Boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Validate token without UserDetails
     * Basic validation checking expiration and signature
     *
     * @param token JWT token
     * @return true if valid, false otherwise
     */
    public Boolean validateToken(String token) {
        try {
            extractAllClaims(token);
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check if token is expired
     *
     * @param token JWT token
     * @return true if expired, false otherwise
     */
    public Boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * Check if token is a refresh token
     *
     * @param token JWT token
     * @return true if refresh token, false otherwise
     */
    public Boolean isRefreshToken(String token) {
        try {
            String tokenType = extractClaim(token, claims -> claims.get("tokenType", String.class));
            return "REFRESH".equals(tokenType);
        } catch (Exception e) {
            return false;
        }
    }

    // ==================== EXTRACT CLAIMS ====================

    /**
     * Extract username from token
     *
     * @param token JWT token
     * @return Username (subject)
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extract user ID from token
     *
     * @param token JWT token
     * @return User ID
     */
    public Long extractUserId(String token) {
        return extractClaim(token, claims -> claims.get("userId", Long.class));
    }

    /**
     * Extract roles from token
     * Returns roles as comma-separated string
     *
     * @param token JWT token
     * @return Roles string (e.g., "ROLE_ADMIN,ROLE_USER")
     */
    public String extractRoles(String token) {
        return extractClaim(token, claims -> claims.get("roles", String.class));
    }

    /**
     * Extract roles as Set
     * Splits comma-separated roles into a Set
     *
     * @param token JWT token
     * @return Set of role strings
     */
    public Set<String> extractRolesAsSet(String token) {
        String rolesStr = extractRoles(token);
        if (rolesStr == null || rolesStr.trim().isEmpty()) {
            return Set.of();
        }
        return Set.of(rolesStr.split(","));
    }

    /**
     * Extract token expiration date
     *
     * @param token JWT token
     * @return Expiration date
     */
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extract token issued date
     *
     * @param token JWT token
     * @return Issued at date
     */
    public Date extractIssuedAt(String token) {
        return extractClaim(token, Claims::getIssuedAt);
    }

    /**
     * Extract specific claim using a resolver function
     * Generic method to extract any claim
     *
     * @param token JWT token
     * @param claimsResolver Function to extract specific claim
     * @param <T> Type of the claim
     * @return Extracted claim value
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extract all claims from token
     *
     * @param token JWT token
     * @return All claims
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Get custom claim by name
     *
     * @param token JWT token
     * @param claimName Name of the claim
     * @return Claim value as Object
     */
    public Object getCustomClaim(String token, String claimName) {
        return extractClaim(token, claims -> claims.get(claimName));
    }

    // ==================== TOKEN REFRESH ====================

    /**
     * Check if token can be refreshed
     * Tokens can be refreshed if they're not expired beyond refresh window
     *
     * @param token JWT token
     * @return true if can be refreshed
     */
    public Boolean canTokenBeRefreshed(String token) {
        try {
            return !isTokenExpired(token) || isRefreshToken(token);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Refresh access token using refresh token
     *
     * @param refreshToken Refresh token
     * @param roles Updated roles (in case roles changed)
     * @return New access token
     */
    public String refreshAccessToken(String refreshToken, Set<String> roles) {
        String username = extractUsername(refreshToken);
        Long userId = extractUserId(refreshToken);
        return generateToken(username, userId, roles);
    }

    // ==================== UTILITY METHODS ====================

    /**
     * Get remaining time until token expiration in milliseconds
     *
     * @param token JWT token
     * @return Remaining time in milliseconds
     */
    public Long getRemainingTimeInMillis(String token) {
        Date expiration = extractExpiration(token);
        return expiration.getTime() - System.currentTimeMillis();
    }

    /**
     * Get remaining time until token expiration in seconds
     *
     * @param token JWT token
     * @return Remaining time in seconds
     */
    public Long getRemainingTimeInSeconds(String token) {
        return getRemainingTimeInMillis(token) / 1000;
    }

    /**
     * Check if token will expire within specified minutes
     * Useful for proactive token refresh
     *
     * @param token JWT token
     * @param minutes Minutes threshold
     * @return true if expiring soon
     */
    public Boolean isTokenExpiringSoon(String token, int minutes) {
        Long remainingMinutes = getRemainingTimeInMillis(token) / (60 * 1000);
        return remainingMinutes <= minutes;
    }

    /**
     * Extract token type (ACCESS or REFRESH)
     *
     * @param token JWT token
     * @return Token type string
     */
    public String getTokenType(String token) {
        return extractClaim(token, claims -> claims.get("tokenType", String.class));
    }

    /**
     * Get token metadata as formatted string
     * Useful for logging and debugging
     *
     * @param token JWT token
     * @return Formatted metadata string
     */
    public String getTokenMetadata(String token) {
        try {
            String username = extractUsername(token);
            Long userId = extractUserId(token);
            String roles = extractRoles(token);
            Date expiration = extractExpiration(token);
            String tokenType = getTokenType(token);

            return String.format(
                    "Token Metadata: [Username: %s, UserId: %s, Roles: %s, Type: %s, Expires: %s]",
                    username, userId, roles, tokenType, expiration
            );
        } catch (Exception e) {
            return "Invalid token";
        }
    }
}