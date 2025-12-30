package com.project.password.manager.dto.response;

import java.time.LocalDateTime;
import java.util.List;

public record SecurityDashboardResponse (
    int totalPasswords,
    int weakPasswords,
    int breachedPasswords,
    int reusedPasswords,
    int expiredPasswords,
    int overallSecurityScore,
    LocalDateTime lastUpdated,
    List<String> recommendations
){}
