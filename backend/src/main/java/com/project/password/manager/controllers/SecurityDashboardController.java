package com.project.password.manager.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/dashboard")
@PreAuthorize("isAuthenticated()")
public class SecurityDashboardController {
    // GET / - security overview
    // GET /weak - list weak passwords
    // GET /breached - list breached passwords
    // GET /expired - list expired passwords
    // GET /reused - list reused passwords
}
