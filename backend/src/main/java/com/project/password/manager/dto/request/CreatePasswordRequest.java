package com.project.password.manager.dto.request;

import jakarta.validation.constraints.NotBlank;
import java.time.LocalDateTime;
import java.util.Set;

public record CreatePasswordRequest(
    @NotBlank String siteName,
    String siteUrl,
    String username,
    @NotBlank String password,
    String notes,
    LocalDateTime expiresAt,
    Set<String> tags
) {}

