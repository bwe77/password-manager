package com.project.password.manager.security;

import com.project.password.manager.models.User;
import com.project.password.manager.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

/**
 * Custom UserDetailsService implementation.
 * 
 * This loads user details from the database for authentication.
 * Integrates with Spring Security's authentication mechanism.
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Load user by email (username in our case).
     * 
     * Called by Spring Security during authentication to verify credentials.
     * Also used by JwtAuthenticationFilter to load user details from token.
     * 
     * @param email User's email address
     * @return UserDetails object for Spring Security
     * @throws UsernameNotFoundException if user not found
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        
        // Find user in database
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
        
        // Convert to Spring Security UserDetails
        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getEmail())
            .password(user.getMasterPasswordHash())  // BCrypt hash
            .authorities(new ArrayList<>())  // No roles/authorities for now
            .accountExpired(false)
            .accountLocked(false)
            .credentialsExpired(false)
            .disabled(false)
            .build();
    }
}