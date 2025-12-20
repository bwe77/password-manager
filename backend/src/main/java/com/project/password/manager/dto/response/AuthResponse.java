package com.project.password.manager.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Builder
public record AuthResponse(
    String accessToken,
    String refreshToken,
    Long userId,
    String email,
    boolean totpEnabled
) {}
