package com.project.password.manager.config;

import org.springframework.boot.micrometer.observation.autoconfigure.ObservationProperties.Http;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;

/**
 * WebClient configuration for external API calls.
 * 
 * Primary use: Have I Been Pwned (HIBP) API for breach detection
 * 
 * Configuration includes:
 * - Connection timeout
 * - Read timeout
 * - Retry logic
 * - User-Agent header (HIBP requires identifying your app)
 */

@Configuration
public class WebClientConfig {
    /**
     * WebClient for Have I Been Pwned API.
     * 
     * HIBP API details:
     * - Base URL: https://api.pwnedpasswords.com/range/
     * - Rate limit: None for range queries (k-anonymity model)
     * - User-Agent: Required (identifies your application)
     * - No API key needed for password breach checks
     */

    @Bean
    public WebClient haveIBeenPwnedWebClient() {
        //Configure timeouts
        HttpClient httpClient = HttpClient.create()
            .responseTimeout(Duration.ofSeconds(10))
            .doOnConnected(conn -> 
                conn.addHandlerLast(new io.netty.handler.timeout.ReadTimeoutHandler(10))
                    .addHandlerLast(new io.netty.handler.timeout.WriteTimeoutHandler(10))
            );

        return WebClient.builder()
            .baseUrl("https://api.pwnedpasswords.com")
            .clientConnector(new ReactorClientHttpConnector(httpClient))
            .defaultHeader("User-Agent", "PasswordManagerApp/1.0")
            .build();
    }

    /**
     * General purpose WebClient for other external API calls.
     * Can be used for future integrations.
     */
    @Bean
    public WebClient webClient() {
        HttpClient httpClient = HttpClient.create()
            .responseTimeout(Duration.ofSeconds(30));

        return WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(httpClient))
            .build();
    }

}
