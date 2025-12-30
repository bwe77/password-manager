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
}
