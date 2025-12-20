package com.project.password.manager.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.project.password.manager.dto.request.AuthRequest;
import com.project.password.manager.dto.request.RegisterRequest;
import com.project.password.manager.dto.response.AuthResponse;
import com.project.password.manager.services.AuthenticationService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationService authenticationService;


    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
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
    public ResponseEntity<?> enableTotp(@RequestHeader("Authorization") String authHeader) {
        // This endpoint will be protected by JWT filter
        // For now, just a placeholder
        return ResponseEntity.ok().body("{\"message\": \"TOTP enable endpoint - implement later\"}");
    }

    // POST /totp/verify
    @PostMapping("/totp/verify")
    public ResponseEntity<?> verifyTotp(@RequestBody String code) {
        // Placeholder for TOTP verification
        return ResponseEntity.ok().body("{\"message\": \"TOTP verify endpoint - implement later\"}");
    }
}
