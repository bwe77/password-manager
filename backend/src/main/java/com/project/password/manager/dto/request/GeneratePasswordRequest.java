package com.project.password.manager.dto.request;

public record GeneratePasswordRequest(
    int length,
    boolean includeUppercase,
    boolean includeLowercase,
    boolean includeNumbers,
    boolean includeSymbols
) {}
