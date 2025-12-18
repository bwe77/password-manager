package com.project.password.manager.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import java.io.IOException;

import jakarta.annotation.Nonnull;


@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // Extract JWT from request
    // Validate token
    // Set authentication in SecurityContext

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
        @Nonnull HttpServletRequest request, 
        @Nonnull HttpServletResponse response, 
        @Nonnull FilterChain filterChain) 
            throws ServletException, IOException {

            final String authHeader = request.getHeader("Authorization");
            final String jwt;
            final String userEmail;
            
            if(authHeader == null || !authHeader.startsWith("Bearer ")){
                filterChain.doFilter(request, response);
                return;
            }

            try {
                // 3. Extract JWT token (remove "Bearer " prefix)
                jwt = authHeader.substring(7);
                
                // 4. Extract username (email) from token
                userEmail = jwtService.extractUsername(jwt);

                // 5. If we have a username and user is not already authenticated
                if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    
                    // 6. Load user details from database
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                    // 7. Validate token
                    if (jwtService.istokenValid(jwt, userDetails.getUsername())) {
                        
                        // 8. Create authentication token
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,  // credentials (password) - not needed after authentication
                                userDetails.getAuthorities()  // user roles/permissions
                        );
                        
                        // 9. Set additional details (IP address, session ID, etc.)
                        authToken.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request)
                        );
                        
                        // 10. Set authentication in SecurityContext
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            } catch (Exception e) {
                // Log the error but don't stop the request
                // This allows public endpoints to still work
                logger.error("JWT authentication failed", e);
            }

            // 11. Continue with the filter chain
            filterChain.doFilter(request, response);
    }
}
