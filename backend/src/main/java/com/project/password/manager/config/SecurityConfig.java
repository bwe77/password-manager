package com.project.password.manager.config;

import com.project.password.manager.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
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
 * Security configuration for the Password Manager application.
 * Configures:
 * - JWT-based authentication (stateless sessions)
 * - CORS for frontend communication
 * - BCrypt password encoding for master passwords
 * - Public vs protected endpoints
 * 
 * Spring Boot 4.0.0 / Spring Security 6.x compatible
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthFilter) {
        this.jwtAuthFilter = jwtAuthFilter;
    }

    /**
     * Main security filter chain configuration.
     * Defines which endpoints are public vs protected.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF - we're using JWT (stateless)
            .csrf(csrf -> csrf.disable())
            
            // Enable CORS with custom configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // Configure authorization rules
            .authorizeHttpRequests(auth -> auth
                // Public endpoints (no authentication required)
                .requestMatchers(
                    "/api/auth/register",
                    "/api/auth/login",
                    "/api/auth/refresh",
                    "/actuator/health",
                    "/actuator/info"
                ).permitAll()
                
                // All other endpoints require authentication
                .anyRequest().authenticated()
            )
            
            // Stateless session management (JWT-based, no server sessions)
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            // Add JWT filter before UsernamePasswordAuthenticationFilter
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * AuthenticationManager bean for manual authentication (login).
     * 
     * Spring Boot auto-configures DaoAuthenticationProvider when it detects
     * UserDetailsService and PasswordEncoder beans, so we don't need to 
     * manually create AuthenticationProvider in Spring Security 6.x.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * BCrypt password encoder for master passwords.
     * 
     * Using BCrypt (strength 12) as a workaround for Spring Boot 4.0.0 Argon2 bug.
     * BCrypt is still highly secure:
     * - Adaptive hashing (gets slower over time as hardware improves)
     * - Built-in salt
     * - Industry standard, battle-tested
     * 
     * Strength 12 = 2^12 = 4096 rounds (takes ~200-300ms to hash)
     * 
     * Note: We'll use Argon2 directly (via de.mkammerer library) for actual password
     * encryption keys, but BCrypt for Spring Security authentication.
     * 
     * Spring Boot will automatically use this for DaoAuthenticationProvider.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
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
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        
        // Allow frontend origin (update for production)
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:4200"));
        
        // Allow common HTTP methods
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        
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