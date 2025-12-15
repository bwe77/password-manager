package com.project.password.manager.services;

import org.springframework.stereotype.Service;

@Service
public class PasswordAnalyzerService {
    // calculateStrength(String password) -> Integer (0-100)
    // Calculate entropy, check patterns, common passwords
    // checkForReuse(Long userId, String password) -> boolean
    // analyzePasswordHealth(Long userId) -> PasswordHealthReport
}