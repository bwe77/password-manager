package com.project.password.manager.config;

import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Configuration
public class WebClientConfig {

    /**
     * WebClient.Builder bean for dependency injection.
     * Required by some services that want to customize the builder.
     */
    @Bean
    public WebClient.Builder webClientBuilder() {
        HttpClient httpClient = HttpClient.create()
            .responseTimeout(Duration.ofSeconds(10))
            .doOnConnected(conn -> 
                conn.addHandlerLast(new ReadTimeoutHandler(10, TimeUnit.SECONDS))
                    .addHandlerLast(new WriteTimeoutHandler(10, TimeUnit.SECONDS))
            );

        return WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(httpClient));
    }

    /**
     * Pre-configured WebClient for Have I Been Pwned API.
     * 
     * HIBP API details:
     * - Base URL: https://api.pwnedpasswords.com
     * - User-Agent: Required (identifies your application)
     * - No API key needed for password breach checks
     */
    @Bean
    public WebClient haveIBeenPwnedWebClient(WebClient.Builder builder) {
        return builder
            .baseUrl("https://api.pwnedpasswords.com")
            .defaultHeader("User-Agent", "PasswordManagerApp/1.0")
            .build();
    }

    /**
     * General purpose WebClient for other external API calls.
     */
    @Bean
    public WebClient webClient(WebClient.Builder builder) {
        HttpClient httpClient = HttpClient.create()
            .responseTimeout(Duration.ofSeconds(30));

        return builder
            .clientConnector(new ReactorClientHttpConnector(httpClient))
            .build();
    }
}