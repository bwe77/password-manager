package com.project.password.manager.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
    @Email String email,
    @NotBlank @Size(min = 12) String masterPassword,
    @NotBlank String masterPasswordConfirm
) {}
