package com.project.password.manager.controllers;

import com.project.password.manager.dto.response.PasswordEntryResponse;
import com.project.password.manager.dto.response.SecurityDashboardResponse;
import com.project.password.manager.repo.PasswordEntryRepository;
import com.project.password.manager.services.SecurityDashboardService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/dashboard")
@PreAuthorize("isAuthenticated()")
public class SecurityDashboardController {
    // GET / - security overview
    // GET /weak - list weak passwords
    // GET /breached - list breached passwords
    // GET /expired - list expired passwords
    // GET /reused - list reused passwords
    private final SecurityDashboardService securityDashboardService;
    private final PasswordEntryRepository passwordEntryRepository;

    public SecurityDashboardController(
            SecurityDashboardService securityDashboardService,
            PasswordEntryRepository passwordEntryRepository
    ) {
        this.securityDashboardService = securityDashboardService;
        this.passwordEntryRepository = passwordEntryRepository;
    }

    @GetMapping("")
    public ResponseEntity<SecurityDashboardResponse> getDashboard(Authentication authentication) {
        Long userId = Long.parseLong(authentication.getName());
        SecurityDashboardResponse dashboard = securityDashboardService.getDashboard(userId);
        return ResponseEntity.ok(dashboard);
    }

    @GetMapping("/weak")
    public ResponseEntity<List<PasswordEntryResponse>> getWeakPasswords(Authentication authentication) {
        Long userId = Long.parseLong(authentication.getName());
        List<PasswordEntryResponse> weakPasswords = passwordEntryRepository
            .findWeakPasswords(userId, 60) 
            .stream()
            .map(entry -> new PasswordEntryResponse(
                entry.getId(), 
                entry.getSiteName(), 
                entry.getSiteUrl(), 
                entry.getUsername(), 
                entry.getCreatedAt(), 
                entry.getLastAccessedAt(), 
                entry.isBreached(), 
                entry.getPasswordStrength(), 
                entry.isFavorite(), 
                null
            ))
            .collect(Collectors.toList());

        return ResponseEntity.ok(weakPasswords);
        
    }

    @GetMapping("/breached")
    public ResponseEntity<List<PasswordEntryResponse>> getBreachedPasswords(Authentication authentication) {
        Long userId = Long.parseLong(authentication.getName());
        List<PasswordEntryResponse> breachedPasswords = passwordEntryRepository
            .findBreachedPasswords(userId) 
            .stream()
            .map(entry -> new PasswordEntryResponse(
                entry.getId(), 
                entry.getSiteName(), 
                entry.getSiteUrl(), 
                entry.getUsername(), 
                entry.getCreatedAt(), 
                entry.getLastAccessedAt(), 
                entry.isBreached(), 
                entry.getPasswordStrength(), 
                entry.isFavorite(), 
                null
            ))
            .collect(Collectors.toList());

        return ResponseEntity.ok(breachedPasswords);
    }

    @GetMapping("/expired")
    public ResponseEntity<List<PasswordEntryResponse>> getExpiredPasswords(Authentication authentication) {
        Long userId = Long.parseLong(authentication.getName());

        List<PasswordEntryResponse> expiredPasswords = passwordEntryRepository
            .findExpiredPasswords(userId, LocalDateTime.now())
            .stream()
            .map(entry -> new PasswordEntryResponse(
                entry.getId(),
                entry.getSiteName(),
                entry.getSiteUrl(),
                entry.getUsername(),
                entry.getCreatedAt(),
                entry.getLastAccessedAt(),
                entry.isBreached(),
                entry.getPasswordStrength(),
                entry.isFavorite(),
                null
            ))
            .collect(Collectors.toList());
        
        return ResponseEntity.ok(expiredPasswords);
    }
}
