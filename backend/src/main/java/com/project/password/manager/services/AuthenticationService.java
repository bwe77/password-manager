package com.project.password.manager.services;

import java.time.LocalDateTime;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.project.password.manager.config.JwtProperties;
import com.project.password.manager.dto.request.AuthRequest;
import com.project.password.manager.dto.request.RegisterRequest;
import com.project.password.manager.dto.response.AuthResponse;
import com.project.password.manager.models.RefreshToken;
import com.project.password.manager.models.User;
import com.project.password.manager.repo.RefreshTokenRepository;
import com.project.password.manager.repo.UserRepository;
import com.project.password.manager.security.Argon2Service;
import com.project.password.manager.security.JwtService;
import com.project.password.manager.security.TotpService;

@Service
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final Argon2Service argon2Service;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository; // NEW
    private final TotpService totpService;                       // NEW
    private final JwtProperties jwtProperties;                   // NEW

    public AuthenticationService(
            JwtService jwtService,
            UserRepository userRepository,
            Argon2Service argon2Service,
            AuthenticationManager authenticationManager,
            PasswordEncoder passwordEncoder,
            RefreshTokenRepository refreshTokenRepository,
            TotpService totpService,
            JwtProperties jwtProperties) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.argon2Service = argon2Service;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenRepository = refreshTokenRepository;
        this.totpService = totpService;
        this.jwtProperties = jwtProperties;
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (!request.masterPassword().equals(request.masterPasswordConfirm())) {
            throw new IllegalArgumentException("Passwords do not match");
        }
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already registered");
        }

        User newUser = new User();
        newUser.setEmail(request.email());
        newUser.setMasterPasswordHash(passwordEncoder.encode(request.masterPassword()));
        newUser.setSalt(argon2Service.generateSalt());
        newUser.setCreatedAt(LocalDateTime.now());
        newUser.setLastLoginAt(LocalDateTime.now());
        userRepository.save(newUser);

        return issueTokens(newUser);
    }

    @Transactional
    public AuthResponse login(AuthRequest request) {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.email(), request.masterPassword())
        );

        User user = userRepository.findByEmail(request.email())
            .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // TOTP enforcement — now actually verifies the code
        if (user.isTotpEnabled()) {
            if (request.totpCode() == null || request.totpCode().isEmpty()) {
                throw new IllegalArgumentException("TOTP code required");
            }
            if (!totpService.verifyCode(user.getTotpSecret(), request.totpCode())) {
                throw new IllegalArgumentException("Invalid TOTP code");
            }
        }

        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        return issueTokens(user);
    }

    public AuthResponse refreshToken(String refreshToken) {
        String email = jwtService.extractUsername(refreshToken);

        User user = userRepository.findByEmail(email)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // Signature/expiry check (cryptographic)...
        if (!jwtService.istokenValid(refreshToken, email)) {
            throw new IllegalArgumentException("Invalid or expired refresh token");
        }
        // ...AND it must still exist in Redis (not revoked). This is the
        // stateful half that makes logout meaningful.
        if (!refreshTokenRepository.existsById(refreshToken)) {
            throw new IllegalArgumentException("Refresh token has been revoked");
        }

        // Token rotation: the old refresh token is single-use. Delete it so a
        // stolen-and-replayed token can't be reused after a legitimate refresh.
        refreshTokenRepository.deleteById(refreshToken);

        return issueTokens(user);
    }

    public void logout(String refreshToken) {
        // Delete from Redis → the token can never pass the existsById check again.
        refreshTokenRepository.deleteById(refreshToken);
    }

    public String enableTotp(Long userId) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // Generate + store the secret, but DO NOT enable yet. Enabling happens
        // only after the user proves they can produce a valid code (verifyTotp).
        String secret = totpService.generateSecret();
        user.setTotpSecret(secret);
        userRepository.save(user);

        return totpService.generateQrCodeDataUri(secret, user.getEmail());
    }

    @Transactional
    public boolean verifyTotp(Long userId, String code) {
        User user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.getTotpSecret() == null) {
            throw new IllegalStateException("TOTP not set up — call enable first");
        }

        boolean valid = totpService.verifyCode(user.getTotpSecret(), code);
        if (valid && !user.isTotpEnabled()) {
            user.setTotpEnabled(true); // flip the switch on first successful verify
            userRepository.save(user);
        }
        return valid;
    }

    // Shared helper: generate both tokens, persist the refresh token in Redis.
    private AuthResponse issueTokens(User user) {
        String accessToken = jwtService.generateToken(user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        RefreshToken stored = new RefreshToken();
        stored.setToken(refreshToken);
        stored.setUserId(user.getId());
        stored.setExpiresAt(LocalDateTime.now()
            .plusSeconds(jwtProperties.getRefreshExpirationMs() / 1000));
        refreshTokenRepository.save(stored);

        return new AuthResponse(
            accessToken, refreshToken, user.getId(), user.getEmail(), user.isTotpEnabled()
        );
    }
}