package com.project.password.manager.dto.response;

import java.time.LocalDateTime;
import java.util.Set;

public record PasswordEntryResponse(
    Long id,
    String siteName,
    String siteUrl,
    String username,
    LocalDateTime createdAt,
    LocalDateTime lastAccessedAt,
    boolean isBreached,
    Integer passwordStrength,
    boolean isFavorite,
    Set<String> tags
) {}
