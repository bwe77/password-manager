package com.project.password.manager.services;

import org.springframework.stereotype.Service;

@Service
public class RateLimitingService {
    // Uses Redis + Bucket4j
    // checkRateLimit(String key, int maxRequests, Duration window) -> boolean
    // Applied to: login attempts, API requests, breach checks
}
