package com.project.password.manager.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

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

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
            //disable csrf - not needed for jwt based authentication
            .csrf().disable()

            //enable cors with custom config
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))

            // configure authorization rules
            .authorizeHttpRequests(auth -> auth
                //public endpoints - no authentication required
                .requestMatchers("/api/auth/register", "/api/auth/login", "/api/auth/refresh", "/actuator/health", "/actuator/info").permitAll()
                //all other endpoints require authentication
                .anyRequest().authenticated()
            ) 

            //stateless session management
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    /**
     * Argon2 password encoder for master passwords.
     * 
     * Argon2 is a memory-hard function that provides protection against:
     * - GPU-based attacks (requires lots of RAM)
     * - Side-channel attacks
     * - Brute-force attacks (intentionally slow)
     * 
     * Parameters:
     * - saltLength: 16 bytes (128 bits)
     * - hashLength: 32 bytes (256 bits)
     * - parallelism: 1 (number of threads)
     * - memory: 65536 KB (64 MB)
     * - iterations: 3
     */

    @Bean
    public PasswordEncoder passwordEncoder(){
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

     /**
     * CORS configuration to allow frontend requests.
     * 
     * Security considerations:
     * - Only allow specific origins (not wildcard "*" in production)
     * - Allow credentials (cookies, authorization headers)
     * - Specify allowed methods explicitly
     */

    @Bean
    public CorsConfigurationSource corsConfigurationSource(){

        CorsConfiguration configuration = new CorsConfiguration();

        //allow frontend origin - adjust for production
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:4200"));

        //allow http methods
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));

        // Allow all headers (can be restricted in production)
        configuration.setAllowedHeaders(List.of("*"));
        
        // Allow credentials (cookies, authorization headers)
        configuration.setAllowCredentials(true);
        
        // Cache preflight requests for 1 hour
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        
        return source;
    }

}