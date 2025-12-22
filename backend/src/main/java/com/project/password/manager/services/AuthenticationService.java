package com.project.password.manager.services;

import java.time.LocalDateTime;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.project.password.manager.dto.request.AuthRequest;
import com.project.password.manager.dto.request.RegisterRequest;
import com.project.password.manager.dto.response.AuthResponse;
import com.project.password.manager.models.User;
import com.project.password.manager.repo.UserRepository;
import com.project.password.manager.security.Argon2Service;
import com.project.password.manager.security.JwtService;
import com.project.password.manager.security.TotpService;

@Service
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    // register(RegisterRequest) -> AuthResponse
    // login(AuthRequest) -> AuthResponse
    // refreshToken(String refreshToken) -> AuthResponse
    // logout(String refreshToken)
    // enableTotp(Long userId) -> String (QR code)
    // verifyTotp(Long userId, String code) -> boolean
    private final UserDetailsService userService;
    private final UserRepository userRepository;
    private final Argon2Service argon2Service;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthenticationService(UserDetailsService userService, JwtService jwtService, UserRepository userRepository,
            Argon2Service argon2Service, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder) {
        // Constructor
        this.userService = userService;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.argon2Service = argon2Service;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Register a new user
     * 
     * Process:
     * 1. Validate passwords match
     * 2. Check if email already exists
     * 3. Hash master password with BCrypt (for authentication)
     * 4. Generate salt for Argon2 (for encryption key derivation)
     * 5. Save user to database
     * 6. Generate JWT tokens
     * 
     * @param request Registration request with email and password
     * @return AuthResponse with tokens and user info
     * @throws IllegalArgumentException if validation fails
     */
    @Transactional
    public AuthResponse register(RegisterRequest request) {
        // Implementation for user registration
        if(!request.masterPassword().equals(request.masterPasswordConfirm())){
            throw new IllegalArgumentException("Passwords do not match");
        }

        //check if email exists
        if(userRepository.existsByEmail(request.email())){
            throw new IllegalArgumentException("Email already registered");
        }

        // Create a new user
        User newUser = new User();
        newUser.setEmail(request.email());

        // Hash the master password with Argon2
        newUser.setMasterPasswordHash(passwordEncoder.encode(request.masterPassword()));

        // Generate salt for Argon2
        newUser.setSalt(argon2Service.generateSalt());

        //set timestamps
        newUser.setCreatedAt(LocalDateTime.now());
        newUser.setLastLoginAt(LocalDateTime.now());

        userRepository.save(newUser);

        // Generate JWT tokens
        String accessToken = jwtService.generateToken(newUser.getEmail());
        String refreshToken = jwtService.generateRefreshToken(newUser.getEmail());

        // Return AuthResponse
        return new AuthResponse(
            accessToken,
            refreshToken,
            newUser.getId(),
            newUser.getEmail(),
            newUser.isTotpEnabled()
        );
    }

    /**
     * Authenticate user and generate tokens
     * 
     * Process:
     * 1. Authenticate with Spring Security (BCrypt verification)
     * 2. Check TOTP if enabled
     * 3. Update last login timestamp
     * 4. Generate JWT tokens
     * 
     * @param request Login request with email, password, and optional TOTP
     * @return AuthResponse with tokens and user info
     * @throws org.springframework.security.authentication.BadCredentialsException if authentication fails
     */
    @Transactional
    public AuthResponse login(AuthRequest request) {
        // Implementation for user login
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.email(), 
                request.masterPassword())
        );

        //load user from database
        User user = userRepository.findByEmail(request.email())
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        //check totp if enabled
        if(user.isTotpEnabled()){
            if(request.totpCode() == null || request.totpCode().isEmpty()){
                throw new IllegalArgumentException("TOTP code required");
            }
             // TODO: Verify TOTP code when TotpService is implemented
        }
        
        // Update last login timestamp
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Generate JWT tokens
        String accessToken = jwtService.generateToken(user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        return new AuthResponse(
            accessToken,
            refreshToken,
            user.getId(),
            user.getEmail(),
            user.isTotpEnabled()
        );
        
    }

    /**
     * Refresh access token using refresh token
     * 
     * @param refreshToken Refresh token from Authorization header
     * @return AuthResponse with new tokens
     * @throws IllegalArgumentException if token is invalid
     */

    public AuthResponse refreshToken(String refreshToken) {
        // Implementation for refreshing JWT token

        //extract email from refresh token
        String email = jwtService.extractUsername(refreshToken);

        //load user
        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));
        
        //validate refresh token
        if(!jwtService.istokenValid(refreshToken, email)){
            throw new IllegalArgumentException("Invalid or expired refresh token");
        }

        // Generate JWT tokens
        String newAccessToken = jwtService.generateToken(user.getEmail());
        String newRefreshToken = jwtService.generateRefreshToken(user.getEmail());

        return new AuthResponse(
            newAccessToken,
            newRefreshToken,
            user.getId(),
            user.getEmail(),
            user.isTotpEnabled()
        );
    }

    /**
     * Logout user by invalidating refresh token
     * 
     * TODO: Store refresh tokens in Redis and remove on logout
     * For now, this is a placeholder since JWTs are stateless
     * 
     * @param refreshToken Refresh token to invalidate
     */
    public void logout(String refreshToken) {
        // TODO: Implement token blacklisting with Redis
        // For now, client-side will discard the tokens
        
        // Future implementation:
        // 1. Extract email from token
        // 2. Remove token from Redis
        // 3. Add token to blacklist with expiration
    }

    /**
     * Enable TOTP for user
     * 
     * @param userId User ID
     * @return QR code data URI for authenticator app
     */
    public String enableTotp(Long userId) {
        // TODO: Implement when TotpService is ready
        throw new UnsupportedOperationException("TOTP not implemented yet");
    }

    /**
     * Verify TOTP code and enable 2FA
     * 
     * @param userId User ID
     * @param code TOTP code from authenticator app
     * @return true if code is valid
     */
    public boolean verifyTotp(Long userId, String code) {
        // TODO: Implement when TotpService is ready
        throw new UnsupportedOperationException("TOTP not implemented yet");
    }


}
