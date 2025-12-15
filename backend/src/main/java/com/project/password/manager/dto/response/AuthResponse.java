package com.project.password.manager.dto.response;

public record AuthResponse(
    String accessToken,
    String refreshToken,
    Long userId,
    String email,
    boolean totpEnabled
) {}
