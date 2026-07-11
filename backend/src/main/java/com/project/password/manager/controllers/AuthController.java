package com.project.password.manager.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.project.password.manager.dto.request.AuthRequest;
import com.project.password.manager.dto.request.RegisterRequest;
import com.project.password.manager.dto.response.AuthResponse;
import com.project.password.manager.models.User;
import com.project.password.manager.repo.UserRepository;
import com.project.password.manager.services.AuthenticationService;

import jakarta.validation.Valid;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;

    public AuthController(AuthenticationService authenticationService, UserRepository userRepository) {
        this.authenticationService = authenticationService;
        this.userRepository = userRepository;
    }

    // POST /register
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authenticationService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // POST /login
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        AuthResponse response = authenticationService.login(request);
        return ResponseEntity.ok(response);
    }

    // POST /refresh
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@RequestHeader("Authorization") String authHeader) {
        // Extract token from "Bearer <token>"
        String refreshToken = authHeader.substring(7);
        AuthResponse response = authenticationService.refreshToken(refreshToken);
        return ResponseEntity.ok(response);
    }

    // POST /logout
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authHeader) {
        String refreshToken = authHeader.substring(7);
        authenticationService.logout(refreshToken);
        return ResponseEntity.noContent().build();
    }

    // POST /totp/enable
    @PostMapping("/totp/enable")
    public ResponseEntity<?> enableTotp(Authentication authentication) {
        Long userId = getUserIdFromAuthHeader(authentication);
        String qrCode = authenticationService.enableTotp(userId);
        return ResponseEntity.ok(Map.of("qrCode", qrCode));
    }

    private Long getUserIdFromAuthHeader(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new RuntimeException("User not found"));
        return user.getId();
    }

    // POST /totp/verify
    @PostMapping("/totp/verify")
    public ResponseEntity<?> verifyTotp(Authentication authentication, @RequestBody Map<String, String> request) {
        Long userId = getUserIdFromAuthHeader(authentication);
        String code = request.get("code");
        boolean verified = authenticationService.verifyTotp(userId, code);
        return ResponseEntity.ok(Map.of("verified", verified));
    }
}
