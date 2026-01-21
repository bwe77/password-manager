package com.project.password.manager.dto.response;

import lombok.Builder;


@Builder
public record AuthResponse(
    String accessToken,
    String refreshToken,
    Long userId,
    String email,
    boolean totpEnabled
) {}
