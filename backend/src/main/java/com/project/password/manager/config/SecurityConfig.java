package com.project.password.manager.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity

// Configure JWT authentication filter
// Set up CORS, CSRF protection
// Define public vs protected endpoints
// Configure password encoder (Argon2)

public class SecurityConfig {

    /**
     * Main security filter chain configuration.
     * Defines which endpoints are public vs protected.
     */

    
}