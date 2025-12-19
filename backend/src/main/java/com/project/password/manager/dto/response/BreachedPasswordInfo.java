package com.project.password.manager.dto.response;

import java.time.LocalDateTime;


/**
 * DTO for breached password information.
 * Used by BreachDetectionService to report compromised passwords.
 */
public record BreachedPasswordInfo(
    Long passwordEntryId,
    String siteName,
    String username,
    LocalDateTime lastBreachCheck,
    boolean isBreached,
    Integer breachCount  // How many times this password appears in breaches (from HIBP)
) {}
