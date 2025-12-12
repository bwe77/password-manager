package com.project.password.manager.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;


@Configuration
@EnableRedisRepositories
public class RedisConfig {
    // Redis template for session storage
    // Rate limiting configuration
    // Cache configuration for breach checks
    
}