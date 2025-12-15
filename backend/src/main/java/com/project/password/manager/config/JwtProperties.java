package com.project.password.manager.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration properties for JWT token management.
 * 
 * Binds properties from application.properties with prefix "jwt"
 * 
 * Usage in application.properties:
 * jwt.secret=your-secret-key
 * jwt.expiration-ms=3600000
 * jwt.refresh-expiration-ms=604800000
 */
@Configuration
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    /**
     * Secret key used for signing JWT tokens.
     * MUST be at least 256 bits (32 characters) for HS256 algorithm.
     * 
     * SECURITY: Change this in production! Use a cryptographically secure random value.
     * Generate using: openssl rand -base64 32
     */
    private String secret;

    /**
     * Access token expiration time in milliseconds.
     * Default: 3600000ms (1 hour)
     * 
     * Short-lived tokens reduce the window of opportunity if stolen.
     */
    private long expirationMs;

    /**
     * Refresh token expiration time in milliseconds.
     * Default: 604800000ms (7 days)
     * 
     * Refresh tokens are stored in Redis and can be revoked.
     */
    private long refreshExpirationMs;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    public void setExpirationMs(long expirationMs) {
        this.expirationMs = expirationMs;
    }

    public long getRefreshExpirationMs() {
        return refreshExpirationMs;
    }

    public void setRefreshExpirationMs(long refreshExpirationMs) {
        this.refreshExpirationMs = refreshExpirationMs;
    }


}

